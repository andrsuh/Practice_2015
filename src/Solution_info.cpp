#include "Solution_info.h"
#include <iostream>


Solution_info * Solution_info::s_info = nullptr;

bool Solution::has_sign_solution() {
    return !sign_solution.empty();
}

bool Solution::has_stat_solution() {
    return !stat_solution.empty();
}

void Solution::print_solution() const {
    std::cout << "Statistical analysis: " << stat_solution << std::endl;
    std::cout << "Signature analysis:   " << sign_solution << std::endl;
    std::cout << std::endl;
}


void Solution_info::display_solution(const Session& session, const Solution& solution) const {
 	if ( !(solution.sign_solution == "none" && solution.stat_solution == "none")) {
    	solution.print_solution();
	}
}

void Solution_info::set_sign_solution(const Session& session, const std::string& solution) {
    solution_list[session].sign_solution = solution;
    if (solution_list[session].has_stat_solution()) {
        display_solution(session, solution_list[session]);
    }
}

void Solution_info::set_stat_solution(const Session& session, const std::string& solution) {
    solution_list[session].stat_solution = solution;
    if (solution_list[session].has_sign_solution()) {
        session.print_session();
        display_solution(session, solution_list[session]);
    }
}
