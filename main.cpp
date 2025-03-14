/**********************************/
/*                                */
/*        Register in chat        */
/*          Hash password         */
/*         Hash data array        */
/*                                */
/**********************************/

#include "sha1.h"
#include "chat.h"

#include <iostream>
#include <string.h>

int main()
{
    Chat chat;
    
    char login[LOGINLENGTH]{ "" };
    char pass[SIZE]{ "" };
    int pass_length{};
    char action{ '\0' };

    do
    {
        std::cout << "1 - register user\n2 - delete user\n3 - login user\n0 - exit\n"
            << "Select action...  ";
        std::cin >> action;

        switch (action)
        {
        case '1':
            std::cout << "Input login: ";
            std::cin >> login;
            std::cout << "Input password: ";
            std::cin >> pass;
            pass_length = sizeof(pass);
            chat.reg(login, pass, pass_length);
            break;
        case '2':
            std::cout << "Input login: ";
            std::cin >> login;
            std::cout << "Input password: ";
            std::cin >> pass;
            pass_length = sizeof(pass);
            chat.del(login, pass, pass_length);
            break;
        case '3':
            std::cout << "Input login: ";
            std::cin >> login;
            std::cout << "Input password: ";
            std::cin >> pass;
            pass_length = sizeof(pass);
            if (chat.login(login, pass, pass_length))
            {
                std::cout << login << " is login\n";
            }
            else
            {
                std::cout << login << " is not login\n";
            }
            break;
        case '0':
            std::cout << "Exit";
        default:
            break;
        } 
    } while (action != '0');
        
	return 0;
}