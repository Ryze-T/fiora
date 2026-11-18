# Go 实验室：目标模块以 go.mod replace 指向 /work（只读挂载）
FROM golang:1.22
WORKDIR /app
COPY lab_test.go /app/
