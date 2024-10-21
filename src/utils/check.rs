use std::fmt::Debug;
use std::time::Instant;

/// Compare and check the result of the function
///
/// # Arguments
///
/// * `cases` - The test cases
/// * `name` - The name of the test
/// * `func` - The function to test
///
/// # Returns
///
/// Returns true if all tests passed; otherwise returns false
pub fn compare_check<I, O, F>(
    cases: Vec<(I, O)>,
    name: &str,
    func: F
) -> bool
where
    I: Clone + Debug,
    O: PartialEq + Debug + Clone,
    F: Fn(&I) -> O
{
    let mut all_tests_passed = true;

    for (input, expected) in cases.iter() {
        let start = Instant::now();
        let result = func(input);
        let duration = start.elapsed();
        print!("Test '{:<65}' {}: {:?}", format!("{:?}", input), name, result);

        if result == *expected {
            println!(" \x1b[32msuccess\x1b[0m in \x1b[35m{:?}\x1b[0m", duration);
        } else {
            println!(" \x1b[31mfailed\x1b[0m in \x1b[35m{:?}\x1b[0m", duration);
            println!("  Expected: {:?}", expected);
            println!("  Got:      {:?}", result);
            all_tests_passed = false;
        }
    }

    if all_tests_passed {
        println!("Test {}: \x1b[32msuccess\x1b[0m", name);
    } else {
        println!("Test {}: \x1b[31mfailed\x1b[0m", name);
    }

    all_tests_passed
}
