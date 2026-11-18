// 实验主体（Java）：真实 sink 驱动 + canary + 正控。目标 sink: {sink}（{src_file}）
import java.io.*;
import java.nio.file.*;

public class Lab {{
    static final String CANARY = "/tmp/lab-canary";
    static final String CMD = "sh -c 'echo PWNED > " + CANARY + "'";

    public static void main(String[] args) throws Exception {{
        // ==== 加载真实代码（只读挂载 /work）====
        // URLClassLoader cl = new URLClassLoader(new java.net.URL[] {{
        //     new File("/work/{src_file}").toURI().toURL() }});
        System.out.println("[ENV ] 目标: /work/{src_file}");

        // ==== 1) 攻击载荷（EXP）====
        // TODO: 按 sink 语义构造（反序列化 gadget / JNDI / 模板注入）。
        // Java 反序列化典型：恶意序列化流喂 ObjectInputStream.readObject。
        Files.deleteIfExists(Paths.get(CANARY));
        // target.entry(attackBytes);                    // ← 打开此行
        boolean fired = Files.exists(Paths.get(CANARY));
        System.out.println("[EXP ] 载荷执行: " + fired);
        if (fired) System.out.println("[RCE ] 任意命令执行实锤 · canary: "
            + new String(Files.readAllBytes(Paths.get(CANARY))).trim());

        // ==== 2) 正控（通道语义真实）====
        // TODO: 正常序列化/解析往返断言。
        System.out.println("[DONE] 实验结束（记录：真代码/桩化边界/canary/正控/分级）");
    }}
}}
