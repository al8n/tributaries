use super::*;

struct PerDir;
impl PrimitiveMachine for PerDir {
  fn capabilities(&self) -> Capabilities {
    Capabilities::new().with_supports_push()
  }
}

struct KernelRecursive;
impl PrimitiveMachine for KernelRecursive {
  fn capabilities(&self) -> Capabilities {
    Capabilities::new()
      .with_supports_push()
      .with_kernel_recursive()
  }
}

struct CustomDescent;
impl PrimitiveMachine for CustomDescent {
  fn capabilities(&self) -> Capabilities {
    Capabilities::new().with_kernel_recursive()
  }

  fn descends(&self) -> bool {
    true
  }
}

#[test]
fn per_directory_backend_descends_by_default() {
  let m = PerDir;
  assert!(!m.capabilities().kernel_recursive());
  assert!(m.descends());
}

#[test]
fn kernel_recursive_backend_does_not_descend_by_default() {
  let m = KernelRecursive;
  assert!(m.capabilities().kernel_recursive());
  assert!(!m.descends());
}

#[test]
fn descends_can_be_overridden() {
  let m = CustomDescent;
  assert!(m.capabilities().kernel_recursive());
  assert!(m.descends());
}
