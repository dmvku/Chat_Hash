#pragma once
#include "sha1.h"
#include <string.h>

#define SIZE 10
#define LOGINLENGTH 10

class Chat
{
public:
    Chat();
    void reg(char _login[LOGINLENGTH], char _pass[], int pass_length);   
    void del(char _login[LOGINLENGTH], char _pass[], int pass_length);
    bool login(char _login[LOGINLENGTH], char _pass[], int pass_length);    
    bool find(char _login[LOGINLENGTH]);
   
private:
    enum enPairStatus {
        free,
        engaged,
        deleted
    };

    struct AuthData {
        AuthData() : login(""), pass_sha1_hash(0), status(enPairStatus::free) {}
        AuthData(char _login[LOGINLENGTH], uint* sh1);
        ~AuthData();       
        
        AuthData& operator = (const AuthData& other);
        bool operator == (const AuthData& other);

        char login[LOGINLENGTH];
        uint* pass_sha1_hash;
        enPairStatus status;
    };

    void add(char _login[LOGINLENGTH], uint* pass_sha1_hash);
    void resize();
    int hash_func(char _login[LOGINLENGTH], int offset);

    AuthData* data;
    int mem_size{ 8 };
    int data_count{ 0 };
};

