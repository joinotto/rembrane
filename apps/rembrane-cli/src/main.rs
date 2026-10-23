use rembrane_domain::{
    EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryRecord,
    MemoryScope, PrincipalId, WorkspaceId,
};

fn main() {
    let command = std::env::args().nth(1);

    match command.as_deref() {
        Some("version" | "--version" | "-V") => {
            println!("rembrane {}", env!("CARGO_PKG_VERSION"));
        }
        Some("demo") => print_demo(),
        _ => print_help(),
    }
}

fn print_demo() {
    let memory = MemoryRecord::confirmed_preference(
        MemoryId::new("memory_demo"),
        WorkspaceId::new("workspace_demo"),
        PrincipalId::new("principal_demo"),
        MemoryScope::Global,
        "Call me Hippo",
        EvidenceReference::new(
            EvidenceId::new("evidence_demo"),
            EvidenceSource::UserStatement,
        ),
    );

    println!("{}: {}", memory.id(), memory.content());
}

fn print_help() {
    println!(
        "Rembrane — your memory across every connected AI\n\n\
         Usage:\n  rembrane version\n  rembrane demo"
    );
}
