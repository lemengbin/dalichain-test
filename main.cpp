#include <iostream>
#include <fstream>
#include "net.h"
#include "key.h"
#include "util.h"
#include "construct_tx.h"

#define VERSION     "1.2"

using namespace std;

static CNet net;

void Help()
{
    cout << "Commands as below:" << endl;
    cout << "q(quit): Quit" << endl;
    cout << "h(? help): Print help information" << endl;
    cout << "v(version): Print version information" << endl;
    cout << "1: Create a common transaction" << endl;
    cout << "2: Create a multisig transaction" << endl;
    cout << "3: Create a token publish transaction" << endl;
    cout << "4: Create a token exchange transaction" << endl;
    cout << "5: Create a contract transaction" << endl;
}

void Version()
{
    cout << "Version: " << VERSION << ", update time: 2019-12-19" << endl;
    cout << "Copyright 2019-2030, Andy Le" << endl;
    cout << "Contract us: lemengbin@163.com or mengbin.le@wealedger.com" << endl;
}

int main(int argc, char** argv)
{
    if(argc != 3 && argc != 5)
    {
        cout << "Tx Constructor need remote node ip and port (and optional command and optional json file)." << endl;
        return 1;
    }

    net.Start(argv[1], (unsigned short)(atoi(argv[2])));
    ECC_Start();

    if(argc == 3)
    {
        cout << endl <<  "Welcome to use tx constructor console..." << endl;
        while(true)
        {
            cout << "Please input command and json file: ";

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
            else if(strCommand == "v" || strCommand == "version")
            {
                Version();
                continue;
            }
            else if(strCommand.size() != 1 || strCommand[0] < '1' || strCommand[0] > '5')
            {
                cout << "Invalid command, retry..." << endl;
                continue;
            }

            cin >> strFile;

            if(strCommand == "q" || strCommand == "quit")
                break;
            else if(strCommand == "h" || strCommand == "?" || strCommand == "help")
                Help();
            else if(strCommand == "v" || strCommand == "version")
                Version();
            else if(strCommand == "1" || strCommand == "2" || strCommand == "3" || strCommand == "4" || strCommand == "5")
                CreateTransaction(strCommand, strFile, net.hSocket);
            else
                cout << "Invalid command, retry..." << endl;
        }
    }
    else
    {
        string strCommand = argv[3];
        ToLowerCase(strCommand);

        if(strCommand == "h" || strCommand == "?" || strCommand == "help")
            Help();
        else if(strCommand == "v" || strCommand == "version")
            Version();
        else if(strCommand.size() != 1 || strCommand[0] < '1' || strCommand[0] > '5')
            cout << "Invalid command..." << endl;
        else
            CreateTransaction(argv[3], argv[4], net.hSocket);
    }

    ECC_Stop();
    cout << "finish..." << endl;
    return 0;
}
