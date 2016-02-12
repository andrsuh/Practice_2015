#ifndef SOLUTION_INFO_H
#define SOLUTION_INFO_H

#include <map>
#include "Session.h"

struct Solution {
    std::string sign_solution;
    std::string stat_solution;

    explicit Solution(){}; // : sign_solution(""), stat_solution("") {}

    bool has_sign_solution();
    bool has_stat_solution();
    void print_solution() const;
};

class Solution_info {
private:
    static Solution_info * s_info;
    std::map<Session, Solution> solution_list;

    Solution_info(){};

    void display_solution(const Session& session, const Solution& solution) const;
public:
    static Solution_info * get_session_info() {
        if (s_info == nullptr) {
            s_info = new Solution_info();
        }
        return s_info;
    };

    ~Solution_info() {
        delete s_info;
    }

    void set_sign_solution(const Session& session, const std::string& solution);
    void set_stat_solution(const Session& session, const std::string& solution);
};

#endif // SOLUTION_INFO_H
