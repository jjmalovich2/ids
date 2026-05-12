#pragma once
#include <vector>
#include <map>
#include <string>
#include <queue>

struct Node {
    std::map<char, Node*> children;
    Node* failure_link = nullptr;
    std::vector<std::string> output;
};

struct AlertMatch {
    std::string signature;
    int offset;
};

class AhoCorasick {
public:
    Node* root;
    int alert_count = 0;

    AhoCorasick();
    ~AhoCorasick(); // clean memory

    void insert(std::string pattern);
    void build_failure_links();
    std::vector<AlertMatch> search(const unsigned char* payload, int len);
};