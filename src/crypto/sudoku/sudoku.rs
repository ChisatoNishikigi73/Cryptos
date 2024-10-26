//! Sudoku implementation
//! 
//! Sudoku is a logic puzzle that is based on a 9x9 grid, where each cell can contain a number from 1 to 9
//! The goal is to fill the grid such that each row, column, and 3x3 box contains all the numbers from 1 to 9 exactly once
//! Background: Sudoku is a popular puzzle that was invented by the Japanese mathematician Takahiro Miyoshi in 1986
//! 
use std::fmt;

/// Represents a Sudoku puzzle.
#[derive(Clone)]
pub struct Sudoku {
    /// The Sudoku board, where 0 represents an empty cell.
    board: [[u8; 9]; 9],
    /// Bitmask for rows to track used numbers.
    rows: [u16; 9],
    /// Bitmask for columns to track used numbers.
    cols: [u16; 9],
    /// Bitmask for 3x3 boxes to track used numbers.
    boxes: [u16; 9],
    /// Flag to determine if steps should be recorded.
    record_steps: bool,
    /// Records the steps taken to solve the puzzle.
    steps: Vec<String>,
}

impl Sudoku {
    /// Creates a new Sudoku instance with the given board.
    /// ### Promise to solve Sudoku puzzles within 10ms, and I hope to use pure algorithms to find the limit of solving Sudoku problems
    ///
    /// # Arguments
    ///
    /// * `board` - A 9x9 array representing the initial Sudoku board.
    ///
    /// # Example
    ///
    /// ```
    /// use cryptos::sudoku::Sudoku;
    /// let board = [
    /// [5, 3, 0, 0, 7, 0, 0, 0, 0],
    /// [6, 0, 0, 1, 9, 5, 0, 0, 0],
    /// [0, 9, 8, 0, 0, 0, 0, 6, 0],
    /// [8, 0, 0, 0, 6, 0, 0, 0, 3],
    /// [4, 0, 0, 8, 0, 3, 0, 0, 1],
    /// [7, 0, 0, 0, 2, 0, 0, 0, 6],
    /// [0, 6, 0, 0, 0, 0, 2, 8, 0],
    /// [0, 0, 0, 4, 1, 9, 0, 0, 5],
    /// [0, 0, 0, 0, 8, 0, 0, 7, 9],
    /// ];
    /// let sudoku = Sudoku::new(board)
    ///     .set_record_steps(true)
    ///     .solve();
    /// match sudoku {
    ///     Ok(solved_sudoku) => 
    ///     {
    ///         if solved_sudoku.get_steps().len() > 0 {
    ///             println!("steps: {}", solved_sudoku.get_steps().len());
    ///         }
    ///         solved_sudoku.print_board();
    ///     },
    ///     Err(_) => panic!("Failed to solve Sudoku"),
    /// }
    /// ```
    pub fn new(board: [[u8; 9]; 9]) -> Self {
        let mut sudoku = Sudoku { 
            board,
            rows: [0; 9],
            cols: [0; 9],
            boxes: [0; 9],
            record_steps: false,
            steps: Vec::new(),
        };
        
        // Initialize bitmask
        for row in 0..9 {
            for col in 0..9 {
                let num = board[row][col];
                if num != 0 {
                    sudoku.set_bit(row, col, num);
                }
            }
        }
        
        sudoku
    }

    pub fn from_line(line: &str) -> Self {
        let vec: Vec<u8> = line.chars()
            .map(|c| c.to_digit(10).unwrap() as u8)
            .collect();
        let mut board = [[0u8; 9]; 9];
        for i in 0..9 {
            board[i].copy_from_slice(&vec[i * 9..(i + 1) * 9]);
        }
        Sudoku::new(board)
    }

    /// Sets whether to record the steps taken during solving.
    ///
    /// # Arguments
    ///
    /// * `record` - A boolean indicating if steps should be recorded.
    pub fn set_record_steps(&self, record: bool) -> Self {
        let mut sudoku = self.clone();
        sudoku.record_steps = record;
        if record {
            sudoku.steps.clear();
        }

        sudoku
    }

    /// Checks if placing a number at the specified position is valid.
    ///
    /// # Arguments
    ///
    /// * `row` - The row index.
    /// * `col` - The column index.
    /// * `num` - The number to place.
    ///
    /// # Returns
    ///
    /// * `true` if the placement is valid, otherwise `false`.
    pub fn is_valid(&self, row: usize, col: usize, num: u8) -> bool {
        let bit = 1 << (num - 1);
        let box_index = (row / 3) * 3 + col / 3;
        (self.rows[row] & bit == 0) && (self.cols[col] & bit == 0) && (self.boxes[box_index] & bit == 0)
    }

    /// Sets the bitmask for a given number at the specified position.
    ///
    /// # Arguments
    ///
    /// * `row` - The row index.
    /// * `col` - The column index.
    /// * `num` - The number to set.
    fn set_bit(&mut self, row: usize, col: usize, num: u8) {
        let bit = 1 << (num - 1);
        self.rows[row] |= bit;
        self.cols[col] |= bit;
        let box_index = (row / 3) * 3 + col / 3;
        self.boxes[box_index] |= bit;
    }

    /// Clears the bitmask for a given number at the specified position.
    ///
    /// # Arguments
    ///
    /// * `row` - The row index.
    /// * `col` - The column index.
    /// * `num` - The number to clear.
    fn clear_bit(&mut self, row: usize, col: usize, num: u8) {
        let bit = !(1 << (num - 1));
        self.rows[row] &= bit;
        self.cols[col] &= bit;
        let box_index = (row / 3) * 3 + col / 3;
        self.boxes[box_index] &= bit;
    }

    /// Attempts to solve the Sudoku puzzle and returns a new Sudoku instance with the solution.
    ///
    /// # Returns
    ///
    /// * `Ok(Sudoku)` containing the solved Sudoku if successful.
    /// * `Err(&'static str)` if the puzzle cannot be solved.
    pub fn solve(&self) -> Result<Sudoku, &'static str> {
        let mut sudoku = self.clone();
        if sudoku.solve_recursive(0, 0) {
            Ok(sudoku)
        } else {
            Err("No solution found")
        }
    }

    /// Recursively solves the Sudoku puzzle using backtracking.
    ///
    /// # Arguments
    ///
    /// * `row` - The current row index.
    /// * `col` - The current column index.
    ///
    /// # Returns
    ///
    /// * `true` if the puzzle is solved, otherwise `false`.
    fn solve_recursive(&mut self, row: usize, col: usize) -> bool {
        if row == 9 {
            return true;
        }

        let next_row = if col == 8 { row + 1 } else { row };
        let next_col = (col + 1) % 9;

        if self.board[row][col] != 0 {
            return self.solve_recursive(next_row, next_col);
        }

        for num in 1..=9 {
            if self.is_valid(row, col, num) {
                self.board[row][col] = num;
                self.set_bit(row, col, num);
                
                if self.record_steps {
                    self.steps.push(format!("Place {} at ({}, {})", num, row, col));
                }

                if self.solve_recursive(next_row, next_col) {
                    return true;
                }

                self.board[row][col] = 0;
                self.clear_bit(row, col, num);
                
                if self.record_steps {
                    self.steps.push(format!("Backtrack ({}, {})", row, col));
                }
            }
        }

        false
    }

    /// Retrieves the steps recorded during the solving process.
    ///
    /// # Returns
    ///
    /// * A reference to the vector of step descriptions.
    pub fn get_steps(&self) -> &Vec<String> {
        &self.steps
    }

    /// Retrieves the solved Sudoku board.
    ///
    /// # Returns
    ///
    /// * A reference to the 9x9 array representing the solved Sudoku board.
    /// Like this:
    /// ```
    /// // [8, 1, 2, 7, 5, 3, 6, 4, 9],
    /// // [9, 4, 3, 6, 8, 2, 1, 7, 5],
    /// // [6, 7, 5, 4, 9, 1, 2, 8, 3],
    /// // ...
    /// ```
    pub fn get_board(&self) -> &[[u8; 9]; 9] {
        &self.board
    }

    /// Prints the Sudoku board to the console.
    pub fn print_board(&self) {
        println!("{}", self);
    }

    pub fn to_line(&self) -> String {
        self.board.iter().flat_map(|row| row.iter().map(|&num| num.to_string())).collect::<Vec<String>>().join("")
    }
}

impl fmt::Display for Sudoku {
    /// Formats the Sudoku board for display.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// * A `fmt::Result`.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for row in &self.board {
            for &num in row.iter() {
                if num == 0 {
                    write!(f, ". ")?;
                } else {
                    write!(f, "{} ", num)?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::check::compare_check;

    #[test]
    fn test_sudoku() {
        let test_cases = vec![
            (
                [
                    [8, 0, 0, 0, 0, 0, 0, 0, 0],
                    [0, 0, 3, 6, 0, 0, 0, 0, 0],
                    [0, 7, 0, 0, 9, 0, 2, 0, 0],
                    [0, 5, 0, 0, 0, 7, 0, 0, 0],
                    [0, 0, 0, 0, 4, 5, 7, 0, 0],
                    [0, 0, 0, 1, 0, 0, 0, 3, 0],
                    [0, 0, 1, 0, 0, 0, 0, 6, 8],
                    [0, 0, 8, 5, 0, 0, 0, 1, 0],
                    [0, 9, 0, 0, 0, 0, 4, 0, 0],
                ],
                [
                    [8, 1, 2, 7, 5, 3, 6, 4, 9],
                    [9, 4, 3, 6, 8, 2, 1, 7, 5],
                    [6, 7, 5, 4, 9, 1, 2, 8, 3],
                    [1, 5, 4, 2, 3, 7, 8, 9, 6],
                    [3, 6, 9, 8, 4, 5, 7, 2, 1],
                    [2, 8, 7, 1, 6, 9, 5, 3, 4],
                    [5, 2, 1, 9, 7, 4, 3, 6, 8],
                    [4, 3, 8, 5, 2, 6, 9, 1, 7],
                    [7, 9, 6, 3, 1, 8, 4, 5, 2],
                ],
            ),
            (
                [
                    [5, 3, 0, 0, 7, 0, 0, 0, 0],
                    [6, 0, 0, 1, 9, 5, 0, 0, 0],
                    [0, 9, 8, 0, 0, 0, 0, 6, 0],
                    [8, 0, 0, 0, 6, 0, 0, 0, 3],
                    [4, 0, 0, 8, 0, 3, 0, 0, 1],
                    [7, 0, 0, 0, 2, 0, 0, 0, 6],
                    [0, 6, 0, 0, 0, 0, 2, 8, 0],
                    [0, 0, 0, 4, 1, 9, 0, 0, 5],
                    [0, 0, 0, 0, 8, 0, 0, 7, 9],
                ],
                [
                    [5, 3, 4, 6, 7, 8, 9, 1, 2],
                    [6, 7, 2, 1, 9, 5, 3, 4, 8],
                    [1, 9, 8, 3, 4, 2, 5, 6, 7],
                    [8, 5, 9, 7, 6, 1, 4, 2, 3],
                    [4, 2, 6, 8, 5, 3, 7, 9, 1],
                    [7, 1, 3, 9, 2, 4, 8, 5, 6],
                    [9, 6, 1, 5, 3, 7, 2, 8, 4],
                    [2, 8, 7, 4, 1, 9, 6, 3, 5],
                    [3, 4, 5, 2, 8, 6, 1, 7, 9],
                ],
            ),
        ];
    
        let solve_sudoku = |&input: &[[u8; 9]; 9]| -> [[u8; 9]; 9] {
            let sudoku = Sudoku::new(input)
                .set_record_steps(false)
                .solve();
            
            match sudoku {
                Ok(solved_sudoku) => 
                {
                    if solved_sudoku.get_steps().len() > 0 {
                        println!("steps: {}", solved_sudoku.get_steps().len());
                    }
                    *solved_sudoku.get_board()
                },
                Err(_) => panic!("Failed to solve Sudoku"),
            }
        };
    
        assert!(compare_check(test_cases, "Sudoku Solver - board", solve_sudoku));
    }

    #[test]
    fn test_sudoku_line() {
        let puzzle = vec![
            ("001300002000090500609070080800000000042000310000000006070050104003060000400009600".to_string(),
             "581346972724198563639572481865431729942687315317925846276853194193764258458219637".to_string())
        ];

        let solve_sudoku = |input: &String| -> String {
            Sudoku::from_line(input)
                .set_record_steps(false)
                .solve()
                .expect("Failed to solve Sudoku")
                .to_line()
        };
    
        assert!(compare_check(puzzle, "Sudoku Solver - line", solve_sudoku));
    }
}

