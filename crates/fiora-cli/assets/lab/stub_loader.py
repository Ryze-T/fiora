"""通用桩加载器：只桩重依赖/side-effect 模块，sink 用真代码。
用法：在 lab.py 顶部 `import stub_loader` 后，任何 torch*/transformers*（可配置）
的缺失模块自动落桩；桩模块的属性访问返回自构造占位对象。
"""
import sys
import types
import importlib.abc
import importlib.machinery


class _AutoMeta(type):
    """宽松元类：属性访问拿到可继承/可实例化的占位类。

    真实代码里 `class CMakeExtension(stubbed.Extension)` 这类**子类化**很常见——
    桩属性如果只返回实例，基类位置直接 TypeError（工作台实测撞过）。"""

    def __getattr__(cls, n):
        if n.startswith("__"):
            raise AttributeError(n)
        return _Auto

    def __instancecheck__(cls, inst):
        return True

    def __subclasscheck__(cls, sub):
        return True


class _Auto(metaclass=_AutoMeta):
    """占位类：可实例化、可被继承、可作基类，绝不执行真实逻辑。"""

    def __init__(self, *a, **k):
        pass

    def __getattr__(self, n):
        if n.startswith("__"):
            raise AttributeError(n)
        return _Auto

    @staticmethod
    def get(*a, **k):
        # 探针语义保持 None；staticmethod 保证类级/实例级调用都成立
        # （桩属性返回的是类，`stubbed.cfg.get(...)` 是类级调用）。
        return None

    def __call__(self, *a, **k):
        return _Auto()


class _StubMod(types.ModuleType):
    def __getattr__(self, n):
        if n.startswith("__"):
            raise AttributeError(n)
        return _Auto


class StubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """拦截 PREFIXES 下的模块导入并落桩；KEEP 中的模块放行给真实加载。"""

    PREFIXES = ("torch",)          # 按目标改：如 ("transformers", "torch")
    KEEP = ()                       # 必须真加载的模块名（如被测模块）

    def find_spec(self, name, path=None, target=None):
        if name in self.KEEP:
            return None
        if any(name == p or name.startswith(p + ".") for p in self.PREFIXES):
            return importlib.machinery.ModuleSpec(name, self, is_package=True)
        return None

    def create_module(self, spec):
        m = _StubMod(spec.name)
        m.__path__ = []
        return m

    def exec_module(self, module):
        pass


sys.meta_path.insert(0, StubFinder())
