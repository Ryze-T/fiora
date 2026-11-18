//! Layer-2: lightweight call-chain engine (docs/TAINT-DESIGN.md, M1: Go).
//!
//! 实测边界（层 1）：opengrep taint 同函数 ✅ / 跨函数 ❌ —— 本模块补跨函数。
//! 架构：tree-sitter 一次性抽取为**自有 IR**（此后与语法树/生命周期彻底解耦）
//! → 函数内流摘要（形参→调用实参 / source→返回值）→ 调用图解析
//! → 候选调用点反向 2~3 跳组装 `Evidence.call_chain`。
//!
//! 刻意不做（精度换速度）：points-to / 虚分派 / 跨仓库。歧义解析降级
//! `HopQuality::Unresolved` 透明暴露，收口交给 LLM 判定层。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use fiora_core::{CallHop, HopQuality};

// ---------- IR（自有数据，零生命周期）----------

#[derive(Debug, Clone)]
enum IrExpr {
    Var(String),
    /// 内置 source（r.URL.Query().Get / FormValue / os.Getenv …）
    Source,
    /// 调用（含实参实参表达式；返回值污点仅内置 source 生效——保守）
    Call(Vec<IrExpr>),
    /// 复合（拼接/索引/转换）：实参污点并集
    Composite(Vec<IrExpr>),
    Unknown,
}

#[derive(Debug, Clone)]
enum IrTarget {
    Var(String),
    /// 字段赋值（c.Args = …）：对象整体染污
    Field(String),
}

#[derive(Debug, Clone)]
struct CallSite {
    callee: String,
    recv: Option<IrExpr>,
    args: Vec<IrExpr>,
    line: u32,
}

#[derive(Debug, Clone)]
struct IrAssign {
    left: IrTarget,
    right: IrExpr,
}

#[derive(Debug, Clone)]
struct IrFn {
    id: String,
    name: String,
    pkg: String,
    file: String,
    line: u32,
    end_line: u32,
    params: Vec<String>,
    assigns: Vec<IrAssign>,
    /// 语句级调用（含 if/for 内）：callee、接收者（x.M 的 x）、实参、行
    calls: Vec<CallSite>,
    returns: Vec<IrExpr>,
}

#[derive(Debug, Default)]
pub struct CallIndex {
    funcs: HashMap<String, IrFn>,
    by_name: HashMap<String, Vec<String>>,
    calls: Vec<CallEdge>,
    /// 反向邻接：被调函数 -> 边下标（BFS 从这里走，不再全边扫描）
    by_callee: HashMap<String, Vec<usize>>,
    pub unparsed: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct ArgOrigins {
    params: HashSet<usize>,
    source: bool,
}

#[derive(Debug, Clone)]
struct CallEdge {
    caller: String,
    callee_raw: String,
    /// 建索引期一次性解析（BFS 查询期零解析——大仓性能的生命线）
    callee_resolved: Option<String>,
    /// 实参位 -> 污点源（形参下标/内置 source）——由 FnSummary 构建，派生污点不丢
    arg_origins: HashMap<usize, ArgOrigins>,
}

/// 候选链查询结果。
pub struct ChainResult {
    pub hops: Vec<CallHop>,
    pub closed: bool,
    pub note: Option<String>,
}

// ---------- 内置 source 标识（与层 1 taint 规则对齐）----------

fn is_source_sigil(name: &str) -> bool {
    // 多语言 source 短名（Go/Py/Java/TS）；宁可多标不漏标——误报由判定层收口
    matches!(
        name,
        "Get"
            | "FormValue"
            | "PostFormValue"
            | "PathValue"
            | "Getenv"
            | "Args"
            | "ArgsLen"
            | "get"
            | "getParameter"
            | "getHeader"
            | "getQueryString"
            | "getProperty"
            | "query"
            | "body"
            | "params"
            | "headers"
            | "cookies"
            | "form"
            | "values"
            | "json"
            | "files"
            | "env"
            | "argv"
    )
}

// ---------- 抽取层：tree-sitter → IR ----------

fn txt<'a>(src: &'a str, n: tree_sitter::Node) -> &'a str {
    n.utf8_text(src.as_bytes()).unwrap_or("")
}

/// 扩展名 → (tree-sitter 语法, lane 标签)。**唯一**的语言分派点：解析与抽取
/// 都从这里取，别再各写一套 `if rel.ends_with(..)`。
/// 未知扩展名返回 None —— 宁可不进索引，也不要用别的语言的语法硬解析出一堆
/// 假符号（此前 `.rb` / 未知后缀全部落到 TypeScript 语法上，静默产垃圾）。
fn grammar_for(rel: &str) -> Option<(tree_sitter::Language, &'static str)> {
    let ext = rel.rsplit('.').next()?.to_ascii_lowercase();
    let g = match ext.as_str() {
        "go" => (tree_sitter_go::LANGUAGE.into(), "go"),
        "py" => (tree_sitter_python::LANGUAGE.into(), "py"),
        "java" => (tree_sitter_java::LANGUAGE.into(), "java"),
        "kt" => (tree_sitter_kotlin_ng::LANGUAGE.into(), "kt"),
        "ts" => (tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), "ts"),
        // TSX/JSX 需要 TSX 语法（LANGUAGE_TYPESCRIPT 不认 JSX 标签）
        "tsx" | "jsx" => (tree_sitter_typescript::LANGUAGE_TSX.into(), "ts"),
        "js" => (tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(), "ts"),
        _ => return None,
    };
    Some(g)
}

// ---------- 语言差异表 ----------
//
// 抽取算法只有一套（栈式遍历 → IR 归一）。各语言的差异——函数定义节点、
// 参数表、赋值语句、调用表达式、成员访问、复合表达式——全部下沉到这里。
// 此前每种语言一份 walk_body + expr_from + call_name，五套骨架逐字重复，
// 改一处语义要改五遍，且很容易改漏一种语言。

/// 成员访问节点 → (成员名, 接收者节点)
type MemberParts =
    for<'t> fn(&str, tree_sitter::Node<'t>) -> (String, Option<tree_sitter::Node<'t>>);

/// 调用节点 → (callee 文本, 接收者节点)
type CallParts =
    for<'t> fn(&str, tree_sitter::Node<'t>) -> Option<(String, Option<tree_sitter::Node<'t>>)>;

#[derive(Clone, Copy)]
struct MemberSpec {
    /// 成员访问节点 kind（`a.b` 的语法节点）
    kind: &'static str,
    /// 该节点 → (成员名, 接收者节点)
    parts: MemberParts,
}

/// 内置 source（`get()` / `r.URL.Query()`）落在成员或调用位置时的取法。
#[derive(Clone, Copy, PartialEq)]
enum Sigil {
    /// Go：保留基底污点 + 实参（漏掉基底，多跳链会断在源头）
    RecvThenArgs,
    /// Python：只保留实参
    ArgsOnly,
    /// Java / Kotlin / TS：调用即 source，实参不再计入
    Bare,
}

struct LangSpec {
    /// 函数定义节点 kind
    fn_kinds: &'static [&'static str],
    /// `variable_declarator` 的值命中这些 kind 时也算函数定义（TS 箭头函数）
    fn_value_kinds: &'static [&'static str],
    /// Go：方法名带 receiver 前缀 `(T).M`
    recv_prefix: bool,
    /// 命中了函数节点却取不到名字时，是否继续向下找（只有 TS 会）
    unnamed_descend: bool,
    assign_kinds: &'static [&'static str],
    call_kind: &'static str,
    ret_kinds: &'static [&'static str],
    /// 合成为 Composite 的表达式节点（拼接/索引/模板串/容器…）
    composite_kinds: &'static [&'static str],
    member: Option<MemberSpec>,
    sigil: Sigil,
    params: fn(&str, tree_sitter::Node) -> Vec<String>,
    body: fn(tree_sitter::Node) -> Option<tree_sitter::Node>,
    assign: fn(&LangSpec, &str, tree_sitter::Node) -> Vec<IrAssign>,
    call_parts: CallParts,
    /// 实参容器 → 实参表达式
    args: fn(&LangSpec, &str, tree_sitter::Node) -> Vec<IrExpr>,
}

const GO: LangSpec = LangSpec {
    fn_kinds: &["function_declaration", "method_declaration"],
    fn_value_kinds: &[],
    recv_prefix: true,
    unnamed_descend: false,
    assign_kinds: &["short_var_declaration", "assignment_statement"],
    call_kind: "call_expression",
    ret_kinds: &["return_statement"],
    composite_kinds: &[
        "binary_expression",
        "slice_expression",
        "index_expression",
        "parenthesized_expression",
        "unary_expression",
        "type_conversion_expression",
        "composite_literal",
        "slice_literal",
        "keyed_element",
    ],
    member: Some(MemberSpec {
        kind: "selector_expression",
        parts: parts_go,
    }),
    sigil: Sigil::RecvThenArgs,
    params: params_go,
    body: body_field,
    assign: assign_go,
    call_parts: call_parts_go,
    args: args_field,
};

const PY: LangSpec = LangSpec {
    fn_kinds: &["function_definition"],
    fn_value_kinds: &[],
    recv_prefix: false,
    unnamed_descend: false,
    assign_kinds: &["assignment", "augmented_assignment"],
    call_kind: "call",
    ret_kinds: &["return_statement"],
    composite_kinds: &[
        "binary_operator",
        "subscript",
        "parenthesized_expression",
        "string",
        "concatenated_string",
        "list",
        "tuple",
        "set",
        "dictionary",
        "list_comprehension",
        "set_comprehension",
        "dictionary_comprehension",
        "generator_expression",
        "keyword_argument",
        "list_splat_pattern",
        "string_literal",
    ],
    member: Some(MemberSpec {
        kind: "attribute",
        parts: parts_py,
    }),
    sigil: Sigil::ArgsOnly,
    params: params_py,
    body: body_field,
    assign: assign_py,
    call_parts: call_parts_py,
    args: args_field,
};

const JVM: LangSpec = LangSpec {
    fn_kinds: &["method_declaration", "constructor_declaration"],
    fn_value_kinds: &[],
    recv_prefix: false,
    unnamed_descend: false,
    assign_kinds: &["variable_declarator", "assignment_expression"],
    call_kind: "method_invocation",
    ret_kinds: &["return_statement"],
    composite_kinds: &[
        "binary_expression",
        "cast_expression",
        "parenthesized_expression",
        "array_initializer",
        "ternary_expression",
        "object_creation_expression",
        "update_expression",
    ],
    member: Some(MemberSpec {
        kind: "field_access",
        parts: parts_jvm,
    }),
    sigil: Sigil::Bare,
    params: params_jvm,
    body: body_field,
    assign: assign_jvm,
    call_parts: call_parts_jvm,
    args: args_field,
};

const KT: LangSpec = LangSpec {
    fn_kinds: &["function_declaration"],
    fn_value_kinds: &[],
    recv_prefix: false,
    unnamed_descend: false,
    assign_kinds: &["property_declaration", "assignment"],
    call_kind: "call_expression",
    ret_kinds: &["return_expression"],
    composite_kinds: &[
        "binary_expression",
        "parenthesized_expression",
        "string_template",
        "as_expression",
        "elvis_expression",
        "check_expression",
    ],
    member: Some(MemberSpec {
        kind: "navigation_expression",
        parts: parts_kt,
    }),
    sigil: Sigil::Bare,
    params: params_kt,
    body: body_kt,
    assign: assign_kt,
    call_parts: call_parts_kt,
    args: args_kt,
};

const TS: LangSpec = LangSpec {
    fn_kinds: &[
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
    ],
    fn_value_kinds: &["arrow_function", "function_expression", "function"],
    recv_prefix: false,
    unnamed_descend: true,
    assign_kinds: &["variable_declarator", "assignment_expression"],
    call_kind: "call_expression",
    ret_kinds: &["return_statement"],
    composite_kinds: &[
        "binary_expression",
        "template_string",
        "subscript_expression",
        "parenthesized_expression",
        "array",
        "spread_element",
        "object",
        "pair",
        "new_expression",
        "await_expression",
        "ternary_expression",
    ],
    member: Some(MemberSpec {
        kind: "member_expression",
        parts: parts_ts,
    }),
    sigil: Sigil::Bare,
    params: params_ts,
    body: body_field,
    assign: assign_ts,
    call_parts: call_parts_ts,
    args: args_field,
};

fn spec_of(lang: &str) -> &'static LangSpec {
    match lang {
        "py" => &PY,
        "java" => &JVM,
        "kt" => &KT,
        "ts" => &TS,
        _ => &GO,
    }
}

/// 多语言统一抽取入口：Go/Python/Java/Kotlin/TS → 同一 IR。
fn extract_fns(src: &str, root: tree_sitter::Node, rel: &str, pkg: &str, lang: &str) -> Vec<IrFn> {
    let sp = spec_of(lang);
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        match fn_def(src, n, sp) {
            Some((Some(name), node)) => {
                if let Some(body) = (sp.body)(node) {
                    let mut f = IrFn {
                        id: format!("{pkg}::{name}"),
                        name,
                        pkg: pkg.to_string(),
                        file: rel.to_string(),
                        line: node.start_position().row as u32 + 1,
                        end_line: node.end_position().row as u32 + 1,
                        params: (sp.params)(src, node),
                        assigns: Vec::new(),
                        calls: Vec::new(),
                        returns: Vec::new(),
                    };
                    walk_body(src, body, &mut f, sp);
                    out.push(f);
                }
                // 已收编为函数：不再向下找（函数体里的调用由 walk_body 收）
                continue;
            }
            Some((None, _)) if !sp.unnamed_descend => continue,
            _ => {}
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            stack.push(ch);
        }
    }
    out
}

/// 函数定义节点 → (名字, 承载参数/函数体的节点)。`Some((None, _))` 表示
/// 命中了函数 kind 但取不到名字——由调用方决定要不要继续向下。
fn fn_def<'t>(
    src: &str,
    n: tree_sitter::Node<'t>,
    sp: &LangSpec,
) -> Option<(Option<String>, tree_sitter::Node<'t>)> {
    if sp.fn_kinds.contains(&n.kind()) {
        let name = n.child_by_field_name("name").map(|x| {
            let mut name = txt(src, x).to_string();
            if sp.recv_prefix && n.kind() == "method_declaration" {
                if let Some(recv) = n.child_by_field_name("receiver") {
                    let t = txt(src, recv).replace(['(', ')', ' '], "");
                    name = format!("({t}).{name}");
                }
            }
            name
        });
        return Some((name, n));
    }
    if n.kind() == "variable_declarator" && !sp.fn_value_kinds.is_empty() {
        let value = n.child_by_field_name("value")?;
        if sp.fn_value_kinds.contains(&value.kind()) {
            let name = n
                .child_by_field_name("name")
                .map(|x| txt(src, x).to_string());
            return Some((name, value));
        }
    }
    None
}

/// 语句级遍历：先序、非递归（大函数不爆栈）。赋值/调用/返回由语言表分派，
/// 遍历本身与语言无关。
fn walk_body(src: &str, body: tree_sitter::Node, f: &mut IrFn, sp: &LangSpec) {
    let mut nodes = vec![body];
    let mut i = 0;
    while i < nodes.len() {
        let n = nodes[i];
        i += 1;
        if sp.assign_kinds.contains(&n.kind()) {
            f.assigns.extend((sp.assign)(sp, src, n));
        } else if n.kind() == sp.call_kind {
            if let Some(c) = call_site(sp, src, n) {
                f.calls.push(c);
            }
        } else if sp.ret_kinds.contains(&n.kind()) {
            let mut c = n.walk();
            let kids: Vec<_> = n.named_children(&mut c).collect();
            f.returns
                .extend(kids.into_iter().map(|ch| expr_of(sp, src, ch)));
        }
        let mut c = n.walk();
        for ch in n.children(&mut c) {
            nodes.push(ch);
        }
    }
}

// ---------- 语言无关的抽取支撑 ----------

fn body_field(n: tree_sitter::Node) -> Option<tree_sitter::Node> {
    n.child_by_field_name("body")
}

/// Kotlin 的函数体按 kind 找（该 grammar 只给 name 打了 field）。
fn body_kt(n: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let mut c = n.walk();
    let kids: Vec<_> = n.named_children(&mut c).collect();
    kids.into_iter().find(|ch| ch.kind() == "function_body")
}

/// 左值归一：标识符 → 变量；成员访问 → 对象整体（`member` 给出节点 kind 与
/// 取对象的字段名）。其余形状（下标、解引用）保守地落 `_`。
fn target_of(src: &str, n: tree_sitter::Node, member: (&str, &str)) -> IrTarget {
    if n.kind() == member.0 {
        return IrTarget::Field(
            n.child_by_field_name(member.1)
                .map(|o| txt(src, o).to_string())
                .unwrap_or_default(),
        );
    }
    if n.kind() == "identifier" {
        return IrTarget::Var(txt(src, n).to_string());
    }
    IrTarget::Var("_".into())
}

/// 成员访问文本 `a.b`（缺哪一半就用另一半）。
fn member_txt(src: &str, n: tree_sitter::Node, recv_field: &str, name_field: &str) -> String {
    let recv = n
        .child_by_field_name(recv_field)
        .map(|o| txt(src, o).to_string());
    let name = n
        .child_by_field_name(name_field)
        .map(|o| txt(src, o).to_string());
    match (recv, name) {
        (Some(a), Some(b)) => format!("{a}.{b}"),
        (None, Some(b)) => b,
        _ => txt(src, n).to_string(),
    }
}

/// 字段型成员访问 → (成员名, 接收者)。
fn member_parts<'t>(
    src: &str,
    n: tree_sitter::Node<'t>,
    name_field: &str,
    recv_field: &str,
) -> (String, Option<tree_sitter::Node<'t>>) {
    (
        n.child_by_field_name(name_field)
            .map(|x| txt(src, x).to_string())
            .unwrap_or_default(),
        n.child_by_field_name(recv_field),
    )
}

fn parts_go<'t>(src: &str, n: tree_sitter::Node<'t>) -> (String, Option<tree_sitter::Node<'t>>) {
    member_parts(src, n, "field", "operand")
}

fn parts_py<'t>(src: &str, n: tree_sitter::Node<'t>) -> (String, Option<tree_sitter::Node<'t>>) {
    member_parts(src, n, "attribute", "object")
}

fn parts_jvm<'t>(src: &str, n: tree_sitter::Node<'t>) -> (String, Option<tree_sitter::Node<'t>>) {
    member_parts(src, n, "field", "object")
}

fn parts_ts<'t>(src: &str, n: tree_sitter::Node<'t>) -> (String, Option<tree_sitter::Node<'t>>) {
    member_parts(src, n, "property", "object")
}

/// Kotlin 的 `navigation_expression` 没有 field：children 是 `[obj, member]`。
fn parts_kt<'t>(src: &str, n: tree_sitter::Node<'t>) -> (String, Option<tree_sitter::Node<'t>>) {
    let mut c = n.walk();
    let parts: Vec<_> = n.named_children(&mut c).collect();
    let Some(member) = parts.last() else {
        return (txt(src, n).to_string(), None);
    };
    let name = txt(src, *member).to_string();
    if parts.len() < 2 {
        return (name, None);
    }
    let obj = parts[0];
    (format!("{}.{}", txt(src, obj), name), Some(obj))
}

/// 成员调用名：`obj.method` → ("obj.method", Some(obj))；其它形状取原文。
fn member_call_name<'t>(
    src: &str,
    func: tree_sitter::Node<'t>,
    member_kind: &str,
    recv_field: &str,
    name_field: &str,
) -> (String, Option<tree_sitter::Node<'t>>) {
    if func.kind() == member_kind {
        let recv = func.child_by_field_name(recv_field);
        return (member_txt(src, func, recv_field, name_field), recv);
    }
    (txt(src, func).to_string(), None)
}

fn call_parts_go<'t>(
    src: &str,
    n: tree_sitter::Node<'t>,
) -> Option<(String, Option<tree_sitter::Node<'t>>)> {
    let func = n.child_by_field_name("function")?;
    Some(member_call_name(
        src,
        func,
        "selector_expression",
        "operand",
        "field",
    ))
}

fn call_parts_py<'t>(
    src: &str,
    n: tree_sitter::Node<'t>,
) -> Option<(String, Option<tree_sitter::Node<'t>>)> {
    let func = n.child_by_field_name("function")?;
    Some(member_call_name(
        src,
        func,
        "attribute",
        "object",
        "attribute",
    ))
}

fn call_parts_jvm<'t>(
    src: &str,
    n: tree_sitter::Node<'t>,
) -> Option<(String, Option<tree_sitter::Node<'t>>)> {
    let recv = n.child_by_field_name("object");
    Some((member_txt(src, n, "object", "name"), recv))
}

fn call_parts_kt<'t>(
    src: &str,
    n: tree_sitter::Node<'t>,
) -> Option<(String, Option<tree_sitter::Node<'t>>)> {
    let mut c = n.walk();
    let head = n.named_children(&mut c).next()?;
    Some(parts_kt(src, head))
}

fn call_parts_ts<'t>(
    src: &str,
    n: tree_sitter::Node<'t>,
) -> Option<(String, Option<tree_sitter::Node<'t>>)> {
    let func = n.child_by_field_name("function")?;
    Some(member_call_name(
        src,
        func,
        "member_expression",
        "object",
        "property",
    ))
}

/// 字段型实参容器（`arguments`）里的实参表达式。
fn args_field(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Vec<IrExpr> {
    let mut out = Vec::new();
    if let Some(a) = n.child_by_field_name("arguments") {
        let mut c = a.walk();
        for ch in a.named_children(&mut c) {
            out.push(expr_of(sp, src, ch));
        }
    }
    out
}

/// Kotlin 的实参在 `value_arguments` 里，每个 `value_argument` 的第一个
/// named child 才是表达式。
fn args_kt(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Vec<IrExpr> {
    let mut out = Vec::new();
    let mut c = n.walk();
    let kids: Vec<_> = n.named_children(&mut c).collect();
    let Some(vargs) = kids.into_iter().find(|p| p.kind() == "value_arguments") else {
        return out;
    };
    let mut vc = vargs.walk();
    for va in vargs.named_children(&mut vc) {
        let mut vac = va.walk();
        for e in va.named_children(&mut vac) {
            out.push(expr_of(sp, src, e));
        }
    }
    out
}

/// 调用点归一：callee、接收者、实参、行号。
fn call_site(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Option<CallSite> {
    let (callee, recv) = (sp.call_parts)(src, n)?;
    Some(CallSite {
        callee,
        recv: recv.map(|o| expr_of(sp, src, o)),
        args: (sp.args)(sp, src, n),
        line: n.start_position().row as u32 + 1,
    })
}

/// 表达式归一：标识符 → 变量；成员访问 → 基底污点或内置 source；调用 →
/// 实参（+ 接收者）污点；复合节点 → 子表达式并集。**唯一**的表达式实现。
fn expr_of(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> IrExpr {
    if n.kind() == "identifier" {
        return IrExpr::Var(txt(src, n).to_string());
    }
    if let Some(m) = sp.member {
        if n.kind() == m.kind {
            let (name, recv) = (m.parts)(src, n);
            if is_source_sigil(&name) {
                // source 标识保留基底污点（r.URL.Query().Get()：r 仍是形参——
                // 否则链在源头断掉，多跳透传无法闭合）
                let mut parts = vec![IrExpr::Source];
                if let Some(r) = recv {
                    parts.push(expr_of(sp, src, r));
                }
                return IrExpr::Composite(parts);
            }
            // 字段读：继承对象污点（x.F 链式）
            return match recv {
                Some(r) => expr_of(sp, src, r),
                None => IrExpr::Unknown,
            };
        }
    }
    if n.kind() == sp.call_kind {
        let Some((callee, recv)) = (sp.call_parts)(src, n) else {
            return IrExpr::Unknown;
        };
        let short = callee.rsplit('.').next().unwrap_or(&callee).to_string();
        if is_source_sigil(&short) {
            let mut parts = vec![IrExpr::Source];
            match sp.sigil {
                Sigil::Bare => return IrExpr::Source,
                Sigil::ArgsOnly => {}
                Sigil::RecvThenArgs => {
                    if let Some(r) = recv {
                        parts.push(expr_of(sp, src, r));
                    }
                }
            }
            parts.extend((sp.args)(sp, src, n));
            return IrExpr::Composite(parts);
        }
        let mut args = (sp.args)(sp, src, n);
        // 接收者污点并入（c.Run()：c 染污即流入）
        if let Some(r) = recv {
            args.push(expr_of(sp, src, r));
        }
        return IrExpr::Call(args);
    }
    if sp.composite_kinds.contains(&n.kind()) {
        let mut parts = Vec::new();
        let mut c = n.walk();
        for ch in n.named_children(&mut c) {
            parts.push(expr_of(sp, src, ch));
        }
        return IrExpr::Composite(parts);
    }
    IrExpr::Unknown
}

// ---------- 各语言的语句级差异 ----------

fn params_go(src: &str, n: tree_sitter::Node) -> Vec<String> {
    let mut out = Vec::new();
    let Some(pl) = n.child_by_field_name("parameters") else {
        return out;
    };
    let mut c = pl.walk();
    for p in pl.named_children(&mut c) {
        if p.kind() != "parameter_declaration" {
            continue;
        }
        let mut pc = p.walk();
        for ch in p.children(&mut pc) {
            if ch.kind() == "identifier" {
                out.push(txt(src, ch).to_string());
            }
        }
    }
    out
}

/// `a, b := x, y`：左表/右表按位 zip。
fn assign_go(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Vec<IrAssign> {
    let mut lefts = Vec::new();
    let mut rights = Vec::new();
    let mut c = n.walk();
    for ch in n.children(&mut c) {
        if ch.kind() != "expression_list" {
            continue;
        }
        let mut cc = ch.walk();
        let items: Vec<_> = ch.named_children(&mut cc).collect();
        if lefts.is_empty() {
            lefts = items;
        } else {
            rights = items;
        }
    }
    lefts
        .iter()
        .zip(rights.iter())
        .map(|(l, r)| IrAssign {
            left: target_of(src, *l, ("selector_expression", "operand")),
            right: expr_of(sp, src, *r),
        })
        .collect()
}

fn params_py(src: &str, n: tree_sitter::Node) -> Vec<String> {
    let mut out = Vec::new();
    let Some(pl) = n.child_by_field_name("parameters") else {
        return out;
    };
    let mut c = pl.walk();
    for p in pl.named_children(&mut c) {
        let nm = match p.kind() {
            "identifier" => Some(txt(src, p).to_string()),
            "typed_parameter"
            | "default_parameter"
            | "typed_default_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => p
                .child_by_field_name("name")
                .map(|x| txt(src, x).to_string()),
            _ => None,
        };
        out.extend(nm);
    }
    out
}

fn assign_py(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Vec<IrAssign> {
    let (Some(l), Some(r)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
    ) else {
        return Vec::new();
    };
    vec![IrAssign {
        left: target_of(src, l, ("attribute", "object")),
        right: expr_of(sp, src, r),
    }]
}

fn params_jvm(src: &str, n: tree_sitter::Node) -> Vec<String> {
    let mut out = Vec::new();
    let Some(pl) = n.child_by_field_name("parameters") else {
        return out;
    };
    let mut c = pl.walk();
    for p in pl.named_children(&mut c) {
        if p.kind() == "formal_parameter" || p.kind() == "spread_parameter" {
            if let Some(nm) = p.child_by_field_name("name") {
                out.push(txt(src, nm).to_string());
            }
        }
    }
    out
}

fn assign_jvm(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Vec<IrAssign> {
    // `int x = …`（variable_declarator）与 `x = …`（assignment_expression）
    if let (Some(l), Some(r)) = (
        n.child_by_field_name("name"),
        n.child_by_field_name("value"),
    ) {
        return vec![IrAssign {
            left: IrTarget::Var(txt(src, l).to_string()),
            right: expr_of(sp, src, r),
        }];
    }
    let (Some(l), Some(r)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
    ) else {
        return Vec::new();
    };
    vec![IrAssign {
        left: target_of(src, l, ("field_access", "object")),
        right: expr_of(sp, src, r),
    }]
}

fn params_kt(src: &str, n: tree_sitter::Node) -> Vec<String> {
    let mut out = Vec::new();
    let mut nc = n.walk();
    let kids: Vec<_> = n.named_children(&mut nc).collect();
    let Some(pl) = kids
        .into_iter()
        .find(|ch| ch.kind() == "function_value_parameters")
    else {
        return out;
    };
    let mut c = pl.walk();
    for p in pl.named_children(&mut c) {
        if p.kind() != "parameter" {
            continue;
        }
        let mut pc = p.walk();
        let ids: Vec<_> = p.named_children(&mut pc).collect();
        if let Some(id) = ids.into_iter().find(|ch| ch.kind() == "identifier") {
            out.push(txt(src, id).to_string());
        }
    }
    out
}

fn assign_kt(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Vec<IrAssign> {
    // `val x = …` / `x = …`：都是前两个 named child；属性声明要先钻进变量声明
    let mut c = n.walk();
    let parts: Vec<_> = n.named_children(&mut c).collect();
    let (target, value) = if n.kind() == "property_declaration" {
        let Some(decl) = parts.first() else {
            return Vec::new();
        };
        let mut dc = decl.walk();
        let lhs = decl
            .named_children(&mut dc)
            .find(|ch| ch.kind() == "identifier")
            .map(|id| txt(src, id).to_string());
        let (Some(lhs), Some(rhs)) = (lhs, parts.get(1)) else {
            return Vec::new();
        };
        (IrTarget::Var(lhs), *rhs)
    } else {
        let (Some(l), Some(r)) = (parts.first(), parts.get(1)) else {
            return Vec::new();
        };
        let target = match l.kind() {
            "identifier" => IrTarget::Var(txt(src, *l).to_string()),
            "navigation_expression" => {
                let (name, recv) = parts_kt(src, *l);
                IrTarget::Field(
                    recv.map(|o| txt(src, o).to_string())
                        .unwrap_or_else(|| name.clone()),
                )
            }
            _ => IrTarget::Var("_".into()),
        };
        (target, *r)
    };
    vec![IrAssign {
        left: target,
        right: expr_of(sp, src, value),
    }]
}

fn params_ts(src: &str, n: tree_sitter::Node) -> Vec<String> {
    let mut out = Vec::new();
    let Some(pl) = n.child_by_field_name("parameters") else {
        return out;
    };
    let mut c = pl.walk();
    for p in pl.named_children(&mut c) {
        let nm = match p.kind() {
            "identifier" => Some(txt(src, p).to_string()),
            "required_parameter" | "optional_parameter" => p
                .child_by_field_name("pattern")
                .map(|x| txt(src, x).to_string()),
            _ => None,
        };
        out.extend(nm);
    }
    out
}

fn assign_ts(sp: &LangSpec, src: &str, n: tree_sitter::Node) -> Vec<IrAssign> {
    let (Some(l), Some(r)) = (
        n.child_by_field_name("name")
            .or_else(|| n.child_by_field_name("left")),
        n.child_by_field_name("value")
            .or_else(|| n.child_by_field_name("right")),
    ) else {
        return Vec::new();
    };
    vec![IrAssign {
        left: target_of(src, l, ("member_expression", "object")),
        right: expr_of(sp, src, r),
    }]
}
// ---------- 流摘要：形参/Source → 调用实参 / 返回值 ----------

#[derive(Default, Clone, Debug)]
struct Origins {
    params: HashSet<usize>,
    source: bool,
}

impl Origins {
    fn merge(&mut self, o: &Origins) -> bool {
        let b = (self.params.len(), self.source);
        self.params.extend(o.params.iter().copied());
        self.source |= o.source;
        b != (self.params.len(), self.source)
    }
}

fn eval_ir(e: &IrExpr, vars: &HashMap<String, Origins>) -> Origins {
    let mut o = Origins::default();
    match e {
        IrExpr::Var(v) => {
            if let Some(x) = vars.get(v) {
                o.merge(x);
            }
        }
        IrExpr::Source => o.source = true,
        IrExpr::Call(args) => {
            for a in args {
                o.merge(&eval_ir(a, vars));
            }
        }
        IrExpr::Composite(ps) => {
            for p in ps {
                o.merge(&eval_ir(p, vars));
            }
        }
        IrExpr::Unknown => {}
    }
    o
}

/// 函数内定点：产出 形参→调用实参 / source→调用实参 / 形参→返回值。
fn summarize_fn(f: &IrFn) -> FnSummary {
    let mut vars: HashMap<String, Origins> = HashMap::new();
    for (i, p) in f.params.iter().enumerate() {
        if p != "_" && !p.is_empty() {
            vars.entry(p.clone()).or_default().params.insert(i);
        }
    }
    // 定点传播
    for _ in 0..5 {
        let mut changed = false;
        for a in &f.assigns {
            let ro = eval_ir(&a.right, &vars);
            match &a.left {
                IrTarget::Var(v) => {
                    changed |= vars.entry(v.clone()).or_default().merge(&ro);
                }
                IrTarget::Field(obj) => {
                    // 字段注入：对象整体染污（c.Args=append(c.Args,arg)）
                    changed |= vars.entry(obj.clone()).or_default().merge(&ro);
                }
            }
        }
        if !changed {
            break;
        }
    }
    let mut s = FnSummary::default();
    for cs in &f.calls {
        // 实参（按位）
        for (j, a) in cs.args.iter().enumerate() {
            let o = eval_ir(a, &vars);
            for p in &o.params {
                s.param_call.push((*p, cs.callee.clone(), j, cs.line));
            }
            if o.source {
                s.source_call.push((cs.callee.clone(), j, cs.line));
            }
        }
        // 接收者污点（c.Args=…; c.Run() 的命脉）：形参/Source 到达该调用
        if let Some(recv) = &cs.recv {
            let o = eval_ir(recv, &vars);
            for p in &o.params {
                s.param_call
                    .push((*p, cs.callee.clone(), usize::MAX, cs.line));
            }
            if o.source {
                s.source_call.push((cs.callee.clone(), usize::MAX, cs.line));
            }
        }
    }
    for r in &f.returns {
        let o = eval_ir(r, &vars);
        s.param_ret.extend(o.params.iter().copied());
        s.source_ret |= o.source;
    }
    s
}

#[derive(Default, Clone, Debug)]
struct FnSummary {
    /// (形参下标, callee 原始名, 实参位, 行)
    param_call: Vec<(usize, String, usize, u32)>,
    /// (callee, 实参位, 行)
    source_call: Vec<(String, usize, u32)>,
    param_ret: HashSet<usize>,
    source_ret: bool,
}

// ---------- 索引与查询 ----------

impl CallIndex {
    pub fn index_repo(root: &Path) -> CallIndex {
        let mut idx = CallIndex::default();
        let mut files = Vec::new();
        collect_source_files(root, &mut files);
        let mut parser = tree_sitter::Parser::new();

        for path in &files {
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            let src = String::from_utf8_lossy(&bytes).to_string();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            let Some((grammar, lane)) = grammar_for(&rel) else {
                idx.unparsed.push(rel);
                continue;
            };
            let lang_res = parser.set_language(&grammar);
            if lang_res.is_err() {
                idx.unparsed.push(rel);
                continue;
            }
            let Some(tree) = parser.parse(&src, None) else {
                idx.unparsed.push(rel);
                continue;
            };
            let pkg = Path::new(&rel)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            for f in extract_fns(&src, tree.root_node(), &rel, &pkg, lane) {
                // 调用边（实参污点在摘要里独立算——这里仅记录边与形参直传）
                // 边由流摘要构建：形参/Source → 实参位（含派生污点）
                let summary = summarize_fn(&f);
                let mut per_callee: HashMap<String, HashMap<usize, ArgOrigins>> = HashMap::new();
                for (p, callee, j, _) in &summary.param_call {
                    per_callee
                        .entry(callee.clone())
                        .or_default()
                        .entry(*j)
                        .or_default()
                        .params
                        .insert(*p);
                }
                for (callee, j, _) in &summary.source_call {
                    per_callee
                        .entry(callee.clone())
                        .or_default()
                        .entry(*j)
                        .or_default()
                        .source = true;
                }
                for (callee, arg_origins) in per_callee {
                    idx.calls.push(CallEdge {
                        caller: f.id.clone(),
                        callee_raw: callee,
                        callee_resolved: None, // 后置解析（函数全量收集后）
                        arg_origins,
                    });
                }
                idx.by_name
                    .entry(f.name.clone())
                    .or_default()
                    .push(f.id.clone());
                idx.funcs.insert(f.id.clone(), f);
            }
        }
        // 后置解析：函数全量收集后再解析边（早解析会漏掉后注册的被调函数）
        let calls = std::mem::take(&mut idx.calls);
        let mut by_callee: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, mut e) in calls.into_iter().enumerate() {
            let caller_pkg = idx
                .funcs
                .get(&e.caller)
                .map(|f| f.pkg.clone())
                .unwrap_or_default();
            e.callee_resolved = idx.resolve(&e.callee_raw, &caller_pkg);
            if let Some(rid) = &e.callee_resolved {
                by_callee.entry(rid.clone()).or_default().push(i);
            }
            idx.calls.push(e);
        }
        idx.by_callee = by_callee;
        idx
    }

    fn resolve(&self, raw: &str, caller_pkg: &str) -> Option<String> {
        let short = raw.rsplit('.').next().unwrap_or(raw);
        let ids = self.by_name.get(short)?;
        // 同包唯一
        let same: Vec<_> = ids
            .iter()
            .filter(|i| i.starts_with(&format!("{caller_pkg}::")))
            .collect();
        if same.len() == 1 {
            return Some(same[0].clone());
        }
        // 限定名 pkg.Func：包尾段匹配唯一
        if raw.contains('.') {
            let hint = raw.split('.').next().unwrap_or("");
            let named: Vec<_> = ids
                .iter()
                .filter(|i| {
                    self.funcs
                        .get(*i)
                        .map(|f| f.pkg.ends_with(hint))
                        .unwrap_or(false)
                })
                .collect();
            if named.len() == 1 {
                return Some(named[0].clone());
            }
        }
        // 全局唯一
        if ids.len() == 1 {
            return Some(ids[0].clone());
        }
        None
    }

    /// 候选调用点（file:line）→ 反向 2~3 跳调用链。
    /// 索引到的函数名（跨语言统一 IR）。诊断与测试断言用：
    /// 「这个文件到底有没有被正确语法解析出来」只能靠它验证。
    pub fn function_names(&self) -> Vec<&str> {
        self.funcs.values().map(|f| f.name.as_str()).collect()
    }

    pub fn trace_chain(&self, file: &str, line: u32) -> ChainResult {
        // 1. 定位收口函数
        let enclosing = self
            .funcs
            .values()
            .filter(|f| f.file == file && f.line <= line && line <= f.end_line)
            .min_by_key(|f| f.end_line - f.line);
        let Some(fn_info) = enclosing else {
            return ChainResult {
                hops: vec![],
                closed: false,
                note: Some("enclosing function not indexed".into()),
            };
        };
        let summary = summarize_fn(fn_info);

        // 2. 种子：该行调用的实参污点（形参或内置 source）
        let mut seeds: HashSet<usize> = HashSet::new();
        let mut direct_source = false;
        for (p, _, _, l) in &summary.param_call {
            if *l == line {
                seeds.insert(*p);
            }
        }
        for (_, _, l) in &summary.source_call {
            if *l == line {
                direct_source = true;
            }
        }
        if seeds.is_empty() && !direct_source {
            return ChainResult {
                hops: vec![],
                closed: false,
                note: Some(format!("no param/source flow to call at {file}:{line}")),
            };
        }

        // 3. 反向 BFS：形参 ← 调用方实参
        let mut hops: Vec<CallHop> = Vec::new();
        let mut closed = direct_source;
        let mut frontier: Vec<(String, HashSet<usize>)> = vec![(fn_info.id.clone(), seeds)];
        let mut visited: HashSet<String> = HashSet::new();
        for _ in 0..3 {
            let mut next = Vec::new();
            for (fn_id, params) in &frontier {
                if !visited.insert(fn_id.clone()) {
                    continue;
                }
                let Some(edge_ids) = self.by_callee.get(fn_id) else {
                    continue;
                };
                for &ei in edge_ids {
                    let edge = &self.calls[ei];
                    let mut caller_seeds: HashSet<usize> = HashSet::new();
                    let mut got = false;
                    for p in params {
                        if let Some(orig) = edge.arg_origins.get(p) {
                            caller_seeds.extend(orig.params.iter().copied());
                            if orig.source {
                                closed = true;
                            }
                            got = true;
                        }
                    }
                    if got {
                        let quality = if self
                            .by_name
                            .get(edge.callee_raw.rsplit('.').next().unwrap_or(""))
                            .map(|v| v.len())
                            .unwrap_or(0)
                            > 1
                        {
                            HopQuality::Unresolved
                        } else {
                            HopQuality::Traced
                        };
                        hops.push(CallHop {
                            from: edge.caller.clone(),
                            to: fn_id.clone(),
                            quality,
                        });
                        if !caller_seeds.is_empty() {
                            next.push((edge.caller.clone(), caller_seeds));
                        }
                    }
                }
            }
            // 入口判定：该函数在索引里无人调用 = 入口 → 链闭合
            for (fn_id, _) in &frontier {
                if !self.by_callee.contains_key(fn_id) {
                    closed = true;
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        // 入口本地流（source 直达候选调用）：给一条自证链（诚实标注为同函数内）
        if direct_source && hops.is_empty() {
            hops.push(CallHop {
                from: fn_info.id.clone(),
                to: fn_info.id.clone(),
                quality: HopQuality::Traced,
            });
        }
        ChainResult {
            hops,
            closed,
            note: if closed {
                None
            } else {
                Some("chain did not close at an entry/source (2-3 hop budget)".into())
            },
        }
    }
}

fn collect_source_files(root: &Path, out: &mut Vec<PathBuf>) {
    const EXTS: &[&str] = &["go", "py", "java", "kt", "ts", "tsx", "js", "jsx"];
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            if name.starts_with('.') || name == "vendor" || name == "node_modules" {
                continue;
            }
            collect_source_files(&p, out);
        } else if p
            .extension()
            .map(|x| EXTS.contains(&x.to_string_lossy().as_ref()))
            .unwrap_or(false)
            && !p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .ends_with("_test.go")
        {
            out.push(p);
        }
    }
}

// ---------- Kotlin 表达式 ----------
//
// Kotlin 有自己的语法（`function_declaration` / `navigation_expression` /
// `value_arguments`），用 Java 语法去 parse 只会静默抽出错误的函数表——
// 所以 .kt 走独立 lane，抽不出就进 `unparsed`，不假装能解析。
