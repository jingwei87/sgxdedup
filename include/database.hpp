#ifndef SGXDEDUP_DATABASE_HPP
#define SGXDEDUP_DATABASE_HPP

#include "dataStructure.hpp"
#include "leveldb/db.h"
#include <bits/stdc++.h>
#include <boost/thread.hpp>
using namespace std;

class Database {
private:
    leveldb::DB* levelDBObj_ = nullptr;
    std::mutex mutexDataBase_;
    std::string dbName_;

public:
    Database() {};
    Database(std::string dbName);
    ~Database();
    bool openDB(std::string dbName);
    bool query(std::string key, std::string& value);
    bool insert(std::string key, std::string value);
    uint64_t getDBSize();
};

#endif //SGXDEDUP_DATABASE_HPP
