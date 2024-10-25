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
#[allow(dead_code)]
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

        let truncated_input = truncate_with_ellipsis(format!("{:?}", input), 62);
        print!("Test '{:<65}' {}: ", truncated_input, name);

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
        println!("");
    } else {
        println!("Test {}: \x1b[31mfailed\x1b[0m", name);
        println!("");
    }

    all_tests_passed
}

/// Truncate the string with ellipsis
fn truncate_with_ellipsis(s: String, max_length: usize) -> String {
    if s.len() <= max_length {
        s
    } else {
        format!("{}...", &s[..max_length - 3])
    }
}

/// Compare and check the result of the function with multiple parameters
/// 
/// # Arguments
/// 
/// * `cases` - The test cases
/// * `name` - The name of the test
/// * `func` - The function to test
/// * `parser` - Function to parse input string into parameters
///
/// # Returns
///
/// Returns true if all tests passed; otherwise returns false
#[allow(dead_code)]
pub fn compare_check_with_params<I, O, P, F, T>(
    cases: Vec<(I, O)>,
    name: &str,
    func: F,
    parser: P,
) -> bool
where
    I: Clone + Debug,
    O: PartialEq + Debug + Clone,
    T: Debug + Clone,
    F: Fn(Vec<T>) -> O,
    P: Fn(&I) -> Vec<T>,
{
    let mut all_tests_passed = true;

    for (input, expected) in cases.iter() {
        let start = Instant::now();
        let params = parser(input);
        let result = func(params.clone());
        let duration = start.elapsed();

        let truncated_input = truncate_with_ellipsis(format!("{:?}", input), 62);
        print!("Test '{:<65}' {}: ", truncated_input, name);

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
        println!("");
    } else {
        println!("Test {}: \x1b[31mfailed\x1b[0m", name);
        println!("");
    }

    all_tests_passed
}
