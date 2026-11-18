# Java 实验室：Temurin + 目标 jar/源码只读挂载
FROM eclipse-temurin:17-jdk
WORKDIR /app
COPY Lab.java /app/
# javac 直接编译 Lab.java；目标类从 /work（只读挂载）加载
