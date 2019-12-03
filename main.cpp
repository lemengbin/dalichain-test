#include <iostream>
#include <fstream>
#include "net.h"
#include "key.h"
#include "util.h"
#include "construct_tx.h"

using namespace std;

static CNet net;

void Help()
{
    cout << "Commands as below:" << endl;
    cout << "q(quit): Quit" << endl;
    cout << "h(? help): Print help information" << endl;
    cout << "1: Create a common transaction" << endl;
    cout << "2: Create a multisig transaction" << endl;
    cout << "3: Create a token publish transaction" << endl;
    cout << "4: Create a token exchange transaction" << endl;
    cout << "5: Create a contract transaction" << endl;
}

int main(int argc, char** argv)
{
    net.Start();
    ECC_Start();

    bool fFirst = true;
    while(true)
    {
        if(fFirst)
        {
            cout << "Please input command and json file: ";
            fFirst = false;
        }
        else
            cout << endl << "Please input command and json file: ";

        string strCommand = "";
        string strFile = "";

        cin >> strCommand;

        ToLowerCase(strCommand);
        if(strCommand == "q" || strCommand == "quit")
            break;
        else if(strCommand == "h" || strCommand == "?" || strCommand == "help")
        {
            Help();
            continue;
        }
        else if(strCommand[0] < '1' || strCommand[0] > '5')
        {
            cout << "Invalid command, retry..." << endl;
            continue;
        }

        cin >> strFile;

        if(strCommand == "q" || strCommand == "quit")
            break;
        else if(strCommand == "h" || strCommand == "?" || strCommand == "help")
            Help();
        else if(strCommand == "1" || strCommand == "2" || strCommand == "3" || strCommand == "4" || strCommand == "5")
            CreateTransaction(strCommand, strFile, net.hSocket);
        else
            cout << "Invalid command, retry..." << endl;
    }

    ECC_Stop();
    cout << "finish..." << endl;
    return 0;
}
