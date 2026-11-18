//! 命令实现分组：每组一个模块，main.rs 只做解析与分发。

pub(crate) mod agent;
pub(crate) mod compose;
pub(crate) mod doctor;
pub(crate) mod eval;
pub(crate) mod family;
pub(crate) mod init;
pub(crate) mod lab;
pub(crate) mod pipeline;
pub(crate) mod report;
pub(crate) mod rules;
pub(crate) mod status;
pub(crate) mod trace;
pub(crate) mod verify;
