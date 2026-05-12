#include "aho_corasick.h"
#include <iostream>

AhoCorasick::AhoCorasick() {
    root = new Node();
}

AhoCorasick::~AhoCorasick() {
    // delete all nodes recursively
}

void AhoCorasick::insert(std::string pattern) {
    Node* curr = root;
    for (char c : pattern) {
        if (curr->children.find(c) == curr->children.end()) {
            curr->children[c] = new Node();
        }
        curr = curr->children[c];
    }
    curr->output.push_back(pattern);
}

void AhoCorasick::build_failure_links() {
    std::queue<Node*> q;
    root->failure_link = root;

    for (auto const& [char_key, child_node] : root->children) {
        child_node->failure_link = root;
        q.push(child_node);
    }

    while (!q.empty()) {
        Node* current = q.front();
        q.pop();

        for (auto const& [char_key, child_node] : current->children) {
            q.push(child_node);
            Node* fallback = current->failure_link;

            while (fallback != root && fallback->children.find(char_key) == fallback->children.end()) {
                fallback = fallback->failure_link;
            }

            if (fallback->children.find(char_key) != fallback->children.end()) {
                child_node->failure_link = fallback->children[char_key];
                child_node->output.insert(child_node->output.end(),
                                          child_node->failure_link->output.begin(),
                                          child_node->failure_link->output.end());
            } else {
                child_node->failure_link = root;
            }
        }
    }
}

std::vector<AlertMatch> AhoCorasick::search(const unsigned char* payload, int len) {
    std::vector<AlertMatch> matches;
    Node* current = root;

    // loop thorugh every byte of the payload
    for (int i = 0; i < len; ++i) {
        // cast unsigned char to char
        char c = static_cast<char>(payload[i]);

        while (current != root && current->children.find(c) == current->children.end()) {
            current = current->failure_link;
        }

        if (current->children.find(c) != current->children.end()) {
            current = current->children[c];
        }

        if (!current->output.empty()) {
            for (const std::string& match : current->output) {
                matches.push_back({match, i - static_cast<int>(match.length()) + 1});
                alert_count++;
            }
        }
    }
    return matches;
}