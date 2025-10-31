// Cryptid.cpp : Defines the entry point for the application.
//
#include "Cryptid.h"
using namespace std;
namespace fs = std::filesystem;

//Variables
bool running = true;

void StartupDisplay() {
	cout << "STARTING CRYPTID" << endl;
	cout << "Cryptid has started \nInput help! to get a list of available commands" << endl;
}

//Commands

//General commands
void CommandHelp(vector<string> args) {
	cout << "AVAILABLE COMMANDS : \n-------------" << endl;

	//Note : in alphabetical order within sections
	cout << "General Commands : " << endl;
	cout << "help! - Lists all available commands" << endl; //Done
	cout << "quit! - Quits the program" << endl; //Done
	cout << "-------------" << endl;

	cout << "Volume Management Commands : " << endl;
	cout << "createVolume! ~folderPath ~volumeName (~owner=_) (~showCreationTimestamp=True) - Creates a new volume at a given folder path with a given volume name" << endl; //Done
	cout << "deleteVolume! ~volumePath - Deletes a volume at a given file path" << endl; //NTS : overwriting passes
	cout << "renameVolume! ~volumePath ~newVolumeName  - Renames a volume at a given file path" << endl;
	cout << "volumeDetails! ~volumePath - Returns details about a volume" << endl; //NTS: size closed, size opened, creation date, owner
	cout << "-------------" << endl;
	
	cout << "File Handling Commands : " << endl;
	cout << "compressExtensionType! ~volumePath ~extensionType - Compresses all files with a given extension type" << endl;
	cout << "copyToVolume! ~volumePath ~filePath - Copies a file to a volume" << endl;
	cout << "deleteFromVolume! ~volumePath ~fileName - Deletes a file from a volume" << endl; //NTS : overwriting passes
	cout << "-------------" << endl;

	cout << "Cryptography Commands : " << endl;
	cout << "decryptVolume! ~volumePath ~password ~nonce (~keyFilePath=None) (~algorithm=AES-GCM) - Decrypts a volume with a password and nonce and optionally a keyfile" << endl;
	cout << "encryptVolume! ~volumePath ~password ~nonce (~keyFilePath=None) (~algorithm=AES-GCM) - Encrypts a volume with a password and nonce and optionally a kyeifle" << endl; //NTS : overwriting passes for opened folder
	cout << "generateKeyFile! ~keyfilePath (~keyFileName=keyfile) - Creates a keyfile at a given path" << endl; //Done
	cout << "-------------" << endl;

	cout << "NOTES : \n-------------" << endl;
	cout << "- Do not use spaces in folder paths - make sure all involved folders have no spaces" << endl;
	cout << "If you do not want to fill an optional argument for a command, use _" << endl;
}

void CommandQuit(vector<string> args) {
	cout << "Goodbye" << endl;
	running = false;
}

//Volume management commands
void CommandCreateVolume(vector<string> args) {

	string path = args[0] + "\\" + args[1];

	if (fs::create_directories(path)) {
		cout << "Volume made at " << path << endl;

		string owner;
		if (args.size() < 3) owner = "_";
		else owner = args[2];

		string timestampStr = "_";
		if (args.size() >= 4) {
			transform(args[3].begin(), args[3].end(), args[3].begin(), ::tolower);
			if (args[3] != "false") {
				time_t timestamp = time(nullptr);
				string timestampStr = ctime(&timestamp);
			}
		}
		else {
			time_t timestamp = time(nullptr);
			string timestampStr = ctime(&timestamp);
		}

		//Creating the information holder for the file
		ofstream volumeInfo(path + "\\VolumeInfo.txt");
		volumeInfo << owner << "," << timestampStr << "," << 0 << "," << 0; //Owner, timestamp, size closed, size opened
		volumeInfo.close();

	}
	else cout << "Volume already exists" << endl;
}

//Cryptography commands
void CommandGenerateKeyFile(vector<string> args) {

	string filename = "keyfile";
	if (args.size() > 1) filename = args[1];

	string path = args[0] + "\\" + filename + ".key";

	ofstream keyFile(path);
	char keyFileStr[4000]; //4 KB keyFile should be long enough
	randombytes_buf(keyFileStr, 4000);
	keyFile << keyFileStr;
	keyFile.close();
}

//Command management
unordered_map<string, function<void(vector<string>)>> commands = {
	{"help!", CommandHelp},
	{"quit!", CommandQuit},
	{"createVolume!", CommandCreateVolume},
	{"generateKeyFile!", CommandGenerateKeyFile }
};

int main(){

	//Variables
	string input;

	//Startup
	StartupDisplay();

	while (running) {
		cout << ">>";
		getline(cin, input);

		//Findig all important data
		istringstream iss(input);
		vector<string> commandSplit;
		string word;

		while (iss >> word) commandSplit.push_back(word);

		vector<string> commandArgs(commandSplit.begin() + 1, commandSplit.end());
		if (commands.contains(commandSplit[0])) commands[commandSplit[0]](commandArgs);
		else cout << "Command unknown" << endl;
	}
	return 0;
}