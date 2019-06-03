pub fn main() {
    let mut database = keepass::database::PwDatabase::new();
    keepass::kdbx::load_kdbx_file("data/test-database.kdbx", &mut database).unwrap();
}
