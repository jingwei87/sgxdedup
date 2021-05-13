#include "database.hpp"

bool Database::query(std::string key, std::string& value)
{
    std::lock_guard<std::mutex> locker(this->mutexDataBase_);
    leveldb::Status queryStatus = this->levelDBObj_->Get(leveldb::ReadOptions(), key, &value);
    return queryStatus.ok();
}

bool Database::insert(std::string key, std::string value)
{
    std::lock_guard<std::mutex> locker(this->mutexDataBase_);
    leveldb::Status insertStatus = this->levelDBObj_->Put(leveldb::WriteOptions(), key, value);
    return insertStatus.ok();
}

uint64_t Database::getDBSize()
{
    std::lock_guard<std::mutex> locker(this->mutexDataBase_);
    leveldb::Iterator* it = this->levelDBObj_->NewIterator(leveldb::ReadOptions());
    uint64_t counter = 0;
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        counter++;
    }
    return counter;
}

bool Database::openDB(std::string dbName)
{
    fstream dbLock;
    dbLock.open("." + dbName + ".lock", std::fstream::in);
    if (dbLock.is_open()) {
        dbLock.close();
        std::cerr << "Database : database locked" << endl;
        return false;
    }
    dbName_ = dbName;

    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, dbName, &this->levelDBObj_);
    assert(status.ok());
    if (status.ok()) {
        return true;
    } else {
        return false;
    }
}

Database::Database(std::string dbName)
{
    this->openDB(dbName);
}

Database::~Database()
{
    std::string name = "." + dbName_ + ".lock";
    remove(name.c_str());
}