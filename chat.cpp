#include "chat.h"

#include <iostream>
#include <string.h>

Chat::Chat()
{    
    data = new AuthData[mem_size];
}

Chat::AuthData::~AuthData()
{
    if (pass_sha1_hash != 0)
    {
        delete[] pass_sha1_hash;
    }
}

Chat::AuthData::AuthData(char _login[LOGINLENGTH], uint* sh1)
{
    memcpy(login, _login, LOGINLENGTH);
    pass_sha1_hash = sh1;
    status = enPairStatus::engaged;
}

Chat::AuthData& Chat::AuthData::operator = (const Chat::AuthData& other)
{
    memcpy(login, other.login, LOGINLENGTH);

    if (pass_sha1_hash != 0)
    {
        delete[] pass_sha1_hash;
    }
        
    pass_sha1_hash = new uint[SHA1HASHLENGTHUINTS];
    memcpy(pass_sha1_hash, other.pass_sha1_hash, SHA1HASHLENGTHBYTES);

    return *this;
}

bool Chat::AuthData::operator == (const Chat::AuthData& other)
{
    return  status == other.status && (status != enPairStatus::engaged
        || (pass_sha1_hash == other.pass_sha1_hash
            && !strcmp(login, other.login)));
}

void Chat::reg(char _login[LOGINLENGTH], char _pass[], int pass_length)
{
    uint* digest = sha1(_pass, pass_length);
    add(_login, digest);        
}

void Chat::del(char _login[LOGINLENGTH], char _pass[], int pass_length)
{
    int index{ -1 };

    // áåðåì ïðîáû ïî âñåì i îò 0 äî ðàçìåðà ìàññèâà
    for (int i{ 0 }; i < mem_size; i++)
    {
        index = hash_func(_login, i);
        if (data[index].status == enPairStatus::free)
        {
            // login not found
            return;
        }

        if (data[index].status == enPairStatus::engaged
            && !memcmp(data[index].login, _login, LOGINLENGTH))
        {
            uint* digest = sha1(_pass, pass_length);
            bool isTrue = !memcmp(data[index].pass_sha1_hash, digest, SHA1HASHLENGTHBYTES);
            delete[] digest;
            if (isTrue)
            {
                // íàéäåíà ÿ÷åéêà, óäàëÿåì åå            
                data[index].status = enPairStatus::deleted;
                data_count--;
                return;
            }
        }
    }
    return;
}

bool Chat::login(char _login[LOGINLENGTH], char _pass[], int pass_length)
{
    int index{ -1 };
    
    for (int i{ 0 }; i < mem_size; i++)
    {
        index = hash_func(_login, i);
        if (data[index].status == enPairStatus::free)
        {
            return false;
        }            
        else if (data[index].status == enPairStatus::engaged
            && !memcmp(_login, data[index].login, LOGINLENGTH))
        {
            uint* digest = sha1(_pass, pass_length);
            bool isTrue = !memcmp(data[index].pass_sha1_hash, digest, SHA1HASHLENGTHBYTES);
            delete[] digest;
            return isTrue;            
        }            
    }
    return false;   
}

bool Chat::find(char _login[LOGINLENGTH])
{
    int index{ -1 };
    
    // áåðåì ïðîáû ïî âñåì i îò 0 äî ðàçìåðà ìàññèâà
    for (int i{ 0 }; i < mem_size; i++)
    {
        index = hash_func(_login, i);
        if (data[index].status == enPairStatus::free)
        {
            // íàéäåíà ïóñòàÿ ÿ÷åéêà
            return false;
        }

        if (data[index].status == enPairStatus::deleted)
        {
            // íàéäåíà óäàëåííàÿ ÿ÷åéêà
            continue;
        }

        if (!memcmp(data[index].login, _login, LOGINLENGTH))
        {
            // íàéäåíà ÿ÷åéêà
            return true;
        }
    }

    return false;
}

void Chat::add(char _login[LOGINLENGTH], uint* pass_sha1_hash)
{
    int index{ -1 };
    int i{ 0 };
    // áåðåì ïðîáû ïî âñåì i îò 0 äî ðàçìåðà ìàññèâà
    for (; i < mem_size; i++)
    {
        index = hash_func(_login, i);

        if (data[index].status == enPairStatus::free || data[index].status == enPairStatus::deleted)
        {
            // íàéäåíà ïóñòàÿ èëè óäàëåííàÿ ÿ÷åéêà, çàíèìàåì åå
            data[index] = AuthData(_login, pass_sha1_hash);
            data[index].status = enPairStatus::engaged;
            data_count++;
            return;
        }
    }

    if (i >= mem_size)
    {
        // óâåëè÷åíèå ðàçìåðà ìàññèâà
        resize();
        // ïåðåñ÷åò õåøà
        add(_login, pass_sha1_hash);
    }
}

void Chat::resize()
{
    AuthData* save_old_data = data; // çàïîìèíàåì ñòàðûé ìàññèâ
    int oldSize = mem_size;

    mem_size *= 2;  // óâåëè÷èâàåì ðàçìåð â äâà ðàçà  
    data_count = 0; // îáíóëÿåì êîëè÷åñòâî ýëåìåíòîâ
    data = new AuthData[mem_size]; // âûäåëÿåì íîâóþ ïàìÿòü

    for (int i = 0; i < oldSize; i++) {
        if (save_old_data[i].status == enPairStatus::engaged)
        {
            add(save_old_data[i].login, save_old_data[i].pass_sha1_hash);
        }
    }
}

int Chat::hash_func(char _login[LOGINLENGTH], int offset)
{
    // âû÷èñëÿåì èíäåêñ
    int sum{ 0 };
    const double A{ 0.7 };

    for (int i{ 0 }; i < strlen(_login); i++)
    {
        sum += _login[i];
    }
    int hashLogin{ static_cast<int>(mem_size * (A * sum - static_cast<int>(A * sum))) };
    // êâàäðàòè÷íûå ïðîáû
    return (hashLogin % mem_size + offset * offset) % mem_size;
}
