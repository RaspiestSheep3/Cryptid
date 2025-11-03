// Cryptid.cpp : Defines the entry point for the application.
//
#include "Cryptid.h"
using namespace std;
namespace fs = std::filesystem;

//Command variables
const uint16_t volumeMetadataSize = 4096; //In bytes
const uint16_t keyFileSize = 4096; //In bytes, 4096 should be a good amount
const uint16_t sectorSize = 512; //In bytes, 512 or 4096
const uint8_t chacha20NonceSize = 12; //Fixed I think
const uint8_t bytesForSectorCount = 4; //This should allow up to ~2.2 TB volumes using a 512B sector size, or ~17.6 TB if using 4096B - probably overkill but 3 bytes is too small

//Runtime Variables
bool running = true;

unsigned char passwordHashed[crypto_hash_sha256_BYTES]; //Should be set to 32 bytes
string usedAlgorithm;

string loadedVolumePath;
unsigned char loadedVolumeMetadata[volumeMetadataSize - chacha20NonceSize] = {0};
unsigned char loadedVolumeNonce[chacha20NonceSize] = {0};


//Startup
void StartupDisplay() {
	cout << "STARTING CRYPTID" << endl;
	cout << "Cryptid has started \nInput help to get a list of available commands" << endl;
}

//*Commands
//General commands
void CommandHelp(vector<string> args) {
	cout << "AVAILABLE COMMANDS : \n-------------" << endl;

	//Note : in alphabetical order within sections
	cout << "General Commands : " << endl;
	cout << "help - Lists all available commands" << endl; //Done
	cout << "quit - Quits the program" << endl; //Done
	cout << "-------------" << endl;

	cout << "Volume Management Commands : " << endl;
	cout << "createVolume ~folderPath ~volumeName (~algorithm=ChaCha20) - Creates a new volume at a given folder path with a given volume name and loads it" << endl; //TODO : Add algorithm support for other algorithms
	cout << "deleteVolume - Deletes a volume at a given file path" << endl; //NTS : overwriting passes
	cout << "loadVolume ~volumePath - Targets a volume - the loaded volume is always targeted by commands" << endl;
	cout << "renameVolume ~newVolumeName - Renames a volume at a given file path" << endl;
	cout << "volumeDetails - Returns details about a volume" << endl; //NTS: size closed, size opened
	cout << "-------------" << endl;
	
	cout << "File Handling Commands : " << endl;
	cout << "compressExtensionType ~extensionType - Compresses all files with a given extension type" << endl;
	cout << "copyToVolume ~filePath - Copies a file to a volume" << endl; //TODO : Add algorithm support to metadata and use that
	cout << "deleteFromVolume ~fileName - Deletes a file from a volume" << endl; //NTS : overwriting passes
	cout << "extractFromVolume ~fileName - Extracts a file from a volume without deleting the original" << endl;
	cout << "-------------" << endl;

	cout << "Cryptography Commands : " << endl;
	cout << "decryptVolume - Fully decrypts a volume" << endl;
	cout << "generateKeyFile ~keyfilePath (~keyFileName=keyfile) - Creates a keyfile at a given path" << endl; //Done
	cout << "loadPassword ~password (~keyFilePath=None) (algorithm=ChaCha20) - Loads in a password + keyfile if passed in, and saves the algorithm" << endl; //Done
	cout << "-------------" << endl;

	cout << "NOTES : \n-------------" << endl;
	cout << "- Do not use spaces in folder paths - make sure all involved folders have no spaces" << endl;
	cout << "- If you do not want to fill an optional argument for a command, use _" << endl;
	cout << "-------------" << endl;
}

void CommandQuit(vector<string> args) {
	cout << "Goodbye" << endl;
	running = false;
}

//Volume management commands

//Has to be out of alphabetical order because CommandCreateVolume calls it
void CommandLoadVolume(vector<string> args) { 
	loadedVolumePath = args[0]; 

	//Getting and decrypting the metadata
	ifstream volume(loadedVolumePath, ios::binary);

	vector<unsigned char> encryptedMetadata(volumeMetadataSize);
	volume.read(reinterpret_cast<char*>(encryptedMetadata.data()), encryptedMetadata.size()); //Reads up to volume metadata size bytes
	encryptedMetadata.resize(volume.gcount()); //Resizes the vector
	volume.close();

	//ChaCha20
	if (usedAlgorithm == "ChaCha20") {
		memcpy(loadedVolumeNonce, encryptedMetadata.data(), chacha20NonceSize);

		encryptedMetadata = vector<unsigned char>(encryptedMetadata.begin() + 12, encryptedMetadata.end());
		//Putting in a check because we don't encrypt the all 0s
		if (!any_of(encryptedMetadata.begin(), encryptedMetadata.end(), [](unsigned char c) { return c != 0; })) crypto_stream_chacha20_xor(loadedVolumeMetadata, encryptedMetadata.data(), volumeMetadataSize - chacha20NonceSize, loadedVolumeNonce, passwordHashed);
	}
}

void CommandCreateVolume(vector<string> args) {

	string path = args[0] + "\\" + args[1] + ".cpd";

	cout << "Volume made at " << path << endl;

	ofstream volume(path, ios::binary);

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

	//Creating the information holder for the file - this will be fixed according to a command variable
	//At the moment it is blank because we have no metadata
	//Note : sector counting starts from 0
	char metadata[volumeMetadataSize] = {0x00};

	if (usedAlgorithm == "ChaCha20") {
		//Writing the nonce to the first 12 bytes of metadata
		randombytes_buf(metadata, chacha20NonceSize);
	}

	volume.write(metadata, volumeMetadataSize);
	
	volume.close();
	CommandLoadVolume(vector<string>{path});
}

//File management commands
void CommandCopyToVolume(vector<string> args) {
	//Finding first available sector
	uint32_t firstAvailableSector = 0;
	for (int i = 3; i > -1; i--) firstAvailableSector |= ((uint32_t)loadedVolumeMetadata[3 - i] << ((3 - i) * 8));
	cout << "First available sector : " << firstAvailableSector << endl;

	//Checking if we have enough space left
	uint32_t maxAvailableSectors = UINT32_MAX - firstAvailableSector;
	uint32_t sectorsNeeded = ceil(filesystem::file_size(args[0]) / (sectorSize));
	if (sectorsNeeded > maxAvailableSectors) {
		cout << "Not enough space available in this volume. Consider creating a new volume." << endl;
		return;
	}

	//Reading and encrypting each block
	ifstream targetFile(args[0], ios::binary);
	fstream volume(loadedVolumePath, ios::binary | std::ios::in | std::ios::out);
	vector<unsigned char> buffer(sectorSize);

	volume.seekp(volumeMetadataSize + firstAvailableSector*8);

	for (int i = firstAvailableSector; i < firstAvailableSector + sectorsNeeded; i++) {
		targetFile.read(reinterpret_cast<char*>(buffer.data()), sectorSize);
		
		//Making the new nonce
		unsigned char newNonce[chacha20NonceSize];
		memcpy(newNonce, loadedVolumeNonce, chacha20NonceSize);

		for (int j = bytesForSectorCount; j > 0; j--) newNonce[chacha20NonceSize - j] = (i >> ((j - 1) * 8)) & 0xFF;

		unsigned char encryptedData[sectorSize];
		crypto_stream_chacha20_xor(encryptedData, buffer.data(), sectorSize,newNonce, passwordHashed);
		
		//Writing
		volume.write(reinterpret_cast<char*>(encryptedData), targetFile.gcount());
	}

	//Updating the metadata

	//Available section metadata
	uint32_t nextAvailableSector = firstAvailableSector + sectorsNeeded;
	unsigned char newSectorWrite[bytesForSectorCount];
	volume.seekp(chacha20NonceSize);
	for (int i = 0; i < bytesForSectorCount; i++) {
		loadedVolumeMetadata[i] = nextAvailableSector & (1 << (bytesForSectorCount - 1 - i) * 8);
		newSectorWrite[i] = nextAvailableSector & (1 << (bytesForSectorCount - 1 - i) * 8);
	}

	volume.write(reinterpret_cast<char*>(newSectorWrite), 4);

	//Adding the file data to the metadata
	//I think we need to use 4 bytes for each section code 
	//TODO!

	volume.close();
	targetFile.close();
}

//Cryptography commands
void CommandGenerateKeyFile(vector<string> args) {

	string filename = "keyfile";
	if (args.size() > 1) filename = args[1];
	string path = args[0] + "\\" + filename + ".key";

	ofstream keyFile(path, ios::binary);
	char keyFileStr[keyFileSize];
	randombytes_buf(keyFileStr, keyFileSize);
	keyFile.write(keyFileStr, keyFileSize);;
	keyFile.close();
	cout << "Created key file" << endl;
}

void CommandLoadPassword(vector<string> args) {
	const unsigned char* passwordBytes = (unsigned char*)args[0].c_str(); //We need to pass into the hasher a pointer to a char[] I think
	vector<unsigned char> keyFileBytes;
	string buffer;
	//Keyfile
	if (args.size() > 1) {
		ifstream keyfile(args[1], ios::binary);
		keyFileBytes = vector<unsigned char>(
			(istreambuf_iterator<char>(keyfile)),
			istreambuf_iterator<char>()
		);
		keyfile.close();
	}

	vector<unsigned char> totalBytes(args[0].length() + keyFileBytes.size());
	memcpy(totalBytes.data(), passwordBytes, args[0].length()); //Concatenates the 2 together
	memcpy(totalBytes.data() + args[0].length(), keyFileBytes.data(), keyFileBytes.size());

	crypto_hash_sha256(passwordHashed, totalBytes.data(), totalBytes.size());
	
	if (args.size() > 2) usedAlgorithm = args[2];
	else usedAlgorithm = "ChaCha20";
}

//Command management
unordered_map<string, function<void(vector<string>)>> commands = {
	{"help", CommandHelp},
	{"quit", CommandQuit},
	{"createVolume", CommandCreateVolume},
	{"loadVolume", CommandLoadVolume},
	{"copyToVolume", CommandCopyToVolume},
	{"generateKeyFile", CommandGenerateKeyFile},
	{"loadPassword", CommandLoadPassword}
};

int main(){
	//Variables
	string input;

	//Startup
	StartupDisplay();

	while (running) {
		cout << ">>";
		getline(cin, input);

		if (input != "") {
			//Findig all important data
			istringstream iss(input);
			vector<string> commandSplit;
			string word;

			while (iss >> word) commandSplit.push_back(word);

			vector<string> commandArgs(commandSplit.begin() + 1, commandSplit.end());
			if (commands.contains(commandSplit[0])) commands[commandSplit[0]](commandArgs);
			else cout << "Command unknown" << endl;
		}
	}
	return 0;
}