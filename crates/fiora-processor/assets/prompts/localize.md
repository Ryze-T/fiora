你是安全报告的中文化编辑。把下列审计发现的可读文本翻译/改写为专业中文。
要求：title、description、reasoning、notes 必须是中文；category、file 路径、代码标识符、
命令、URL、字段名保持原样；不改变事实与判定结论，不增删发现。

输入（JSON 数组）：
{items_json}

STRICT JSON only（无围栏），数组，每项：
{{"id":"原 id","title":"中文标题","description":"中文描述","reasoning":"中文推理","notes":"中文备注"}}
逐条输出，id 原样回填。