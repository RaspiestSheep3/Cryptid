// Cryptid.cpp : Defines the entry point for the application.
//
#include "Cryptid.h"
using namespace std;
namespace fs = std::filesystem;

//Command variables
const uint64_t volumeMetadataSize = 256 * 256 * 256; //In bytes
const uint16_t keyFileSize = 4096; //In bytes, 4096 should be a good amount
const uint16_t sectorSize = 512; //In bytes, 512 or 4096
const uint8_t chacha20NonceSize = 12; //Fixed I think
const uint8_t bytesForSectorCount = 4; //This should allow up to ~2.2 TB volumes using a 512B sector size, or ~17.6 TB if using 4096B - probably overkill but 3 bytes is too small
//Note so I don't forget how I did this : 2^32 sectors, each sector is 512 bytes so (2^32 * 512) / 10^12 ~= 2.2 TB
const uint8_t lengthBytes = 2;
const uint8_t maxFileLengthName = 118; //In chars
//When combined with the set metadata size, this should support 131072 files in 1 volume
// This is probably overkill but we support 2.2TB so might as well 
//Only issue is the volume Metadata is like 2MB but o well 

//Runtime Variables
bool running = true;

//!REMOVE THIS ASAP THIS SI JUST FOR TESTING
unsigned char passwordHashed[crypto_hash_sha256_BYTES] = { 1 }; //Should be set to 32 bytes
string usedAlgorithm = "ChaCha20";

string loadedVolumePath;
unsigned char loadedVolumeMetadata[volumeMetadataSize - chacha20NonceSize] = {0};
unsigned char loadedVolumeNonce[chacha20NonceSize] = {0};

//Startup
void StartupDisplay() {
	cout << "STARTING CRYPTID" << endl;
	cout << "Cryptid has started \nInput help to get a list of available commands" << endl;
}

//Helper functions
int FindFirst128Zeros(const std::vector<unsigned char>& data) {
	int consecutive = 0;

	for (size_t i = 0; i < data.size(); ++i) {
		if (data[i] == 0x00) {
			consecutive++;
			if (consecutive == 128) {
				return static_cast<int>(i - 127); // start index of the 128 zeros
			}
		}
		else {
			consecutive = 0; // reset counter
		}
	}
	return -1; // not found
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
	cout << "volumeDetails - Returns details about a volume" << endl;
	cout << "-------------" << endl;
	
	cout << "File Handling Commands : " << endl;
	cout << "compressExtensionType ~extensionType - Compresses all files with a given extension type" << endl;
	cout << "copyToVolume ~filePath - Copies a file to a volume" << endl; //TODO : Add algorithm support to metadata and use that
	cout << "copyFolderToVolume ~folderPath - Copies all files in a folder to a volume" << endl; //TODO : Add algorithm support to metadata and use that
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
	cout << "Used algorithm : " << usedAlgorithm << endl;
	if (usedAlgorithm == "ChaCha20") {
		memcpy(loadedVolumeNonce, encryptedMetadata.data(), chacha20NonceSize);

		encryptedMetadata = vector<unsigned char>(encryptedMetadata.begin() + 12, encryptedMetadata.end());


		int snipPoint = FindFirst128Zeros(encryptedMetadata);
		if (snipPoint < 0) snipPoint = snipPoint = encryptedMetadata.size();

		cout << "Snip point : " << dec << snipPoint << endl;

		encryptedMetadata = vector<unsigned char>(encryptedMetadata.begin(), encryptedMetadata.begin() + snipPoint);

		for (int i = 4; i < encryptedMetadata.size(); i += 2 * bytesForSectorCount + lengthBytes + maxFileLengthName) {
			vector<unsigned char> decryptedMetadata(2 * bytesForSectorCount + lengthBytes + maxFileLengthName);

			//cout << "CHACHA20 COUNTER : " << dec << (i - 4) / (2 * bytesForSectorCount + lengthBytes + maxFileLengthName)  << endl;

			crypto_stream_chacha20_xor_ic(decryptedMetadata.data(), encryptedMetadata.data() + i, decryptedMetadata.size(), loadedVolumeNonce, (i - 4) / (2 * bytesForSectorCount + lengthBytes + maxFileLengthName), passwordHashed);
			
			if (all_of(decryptedMetadata.begin(), decryptedMetadata.end(),
				[](unsigned char c) { return c == 0x00 || c == 0xFF; }) || all_of(encryptedMetadata.begin(), encryptedMetadata.begin() + decryptedMetadata.size(),
					[](unsigned char c) { return c == 0x00 || c == 0xFF; }))
			{
				cout << "Stopping" << endl;  break;
			}
			memcpy(loadedVolumeMetadata + i, decryptedMetadata.data(), decryptedMetadata.size());
		}
	}
	for (int i = 0; i < 4; i++) loadedVolumeMetadata[i] = encryptedMetadata[i];
	cout << "Completed loading" << endl;

	//Check 1 - First sections
	cout << hex << "First sections : " << (int)loadedVolumeMetadata[0] << " " << (int)loadedVolumeMetadata[1] << " " << (int)loadedVolumeMetadata[2] << " " << (int)loadedVolumeMetadata[3] << endl;
	//Check 2 - First sections
	cout << hex << "Section A : " << (int)loadedVolumeMetadata[4] << " " << (int)loadedVolumeMetadata[5] << " " << (int)loadedVolumeMetadata[6] << " " << (int)loadedVolumeMetadata[7] << endl;
	cout << hex << "Section B : " << (int)loadedVolumeMetadata[8] << " " << (int)loadedVolumeMetadata[9] << " " << (int)loadedVolumeMetadata[10] << " " << (int)loadedVolumeMetadata[11] << endl;
	cout << hex << "Section C : " << (int)loadedVolumeMetadata[12] << " " << (int)loadedVolumeMetadata[13] << endl;
	cout << hex << "Section D : " << (int)loadedVolumeMetadata[14] << " " << (int)loadedVolumeMetadata[15] << " " << (int)loadedVolumeMetadata[16] << " " << (int)loadedVolumeMetadata[17] << endl;
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
	vector<char> metadata(volumeMetadataSize, 0x00);

	if (usedAlgorithm == "ChaCha20") {
		//Writing the nonce to the first 12 bytes of metadata
		randombytes_buf(metadata.data(), chacha20NonceSize);
	}

	volume.write(metadata.data(), volumeMetadataSize);
	
	volume.close();
	CommandLoadVolume(vector<string>{path});
}

void CommandVolumeDetails(vector<string> args) {
	//Debugging
	cout << "TEMP : Volume metadata debugging : " << (int)loadedVolumeMetadata[0] << " " << (int)loadedVolumeMetadata[1] << " " << (int)loadedVolumeMetadata[2] << " " << (int)loadedVolumeMetadata[3] << endl;
	
	//First available sector
	uint32_t firstAvailableSector = 0;
	for (int i = 0; i < bytesForSectorCount; i++) firstAvailableSector |= (loadedVolumeMetadata[i] << ((bytesForSectorCount - 1 - i) * 8)); //This better work for big-endian
	cout << "First Available Sector : Sector " << firstAvailableSector << endl;
	
	//Space used

	double volumeSize = fs::file_size(fs::path(loadedVolumePath)) - volumeMetadataSize;

	float volumeSizeEdited = 0;
	string volumeSizePrefix = " B";

	if (volumeSize < 1024) volumeSizeEdited = volumeSize;
	else if (volumeSize < 1024 * 1024) { volumeSizeEdited = volumeSize / 1024; volumeSizePrefix = " KB"; }
	else if (volumeSize < 1024 * 1024 * 1024) { volumeSizeEdited = volumeSize / (1024 * 1024); volumeSizePrefix = " MB"; }
	else if (volumeSize < 1024ULL * 1024 * 1024 * 1024) { volumeSizeEdited = volumeSize / (1024 * 1024 * 1024); volumeSizePrefix = " GB"; }
	else if (volumeSize < 1024ULL * 1024 * 1024 * 1024 * 1024) { volumeSizeEdited = volumeSize / (1024ULL * 1024 * 1024 * 1024); volumeSizePrefix = " TB"; }

	cout << "Size of stored files : " << round(volumeSizeEdited * 100 ) / 100 << volumeSizePrefix << endl;

	//Listing each file and how many sectors it uses
	//Each entry has first sector and amount of sectors used
	struct FileEntry {
		uint64_t startSector;
		uint64_t sectorCount;
		string fileName;
	};

	vector<FileEntry> filesInVolume;

	uint16_t charCounter = 4;

	//Visualising an entry
	size_t entrySize = 2 * bytesForSectorCount + lengthBytes + maxFileLengthName;

	while (!all_of(loadedVolumeMetadata + charCounter,
		loadedVolumeMetadata + charCounter + entrySize,
		[](unsigned char c) { return c == 0; }))
	{
		// Debug hex dump of full entry
		for (int i = 2 * bytesForSectorCount + lengthBytes; i < entrySize; i++) {
			if (static_cast<int>(loadedVolumeMetadata[charCounter + i]) == 0xFF) { break; }
			cout << (loadedVolumeMetadata[charCounter + i]);
		}
		cout << dec << endl;

		charCounter += entrySize;
	}
}

//File management commands
void CommandCopyToVolumeOld(vector<string> args) {
	//Looking at the first 4 bytes of metadat
	cout << "Metadata : " << dec << (int)loadedVolumeMetadata[0] << " " << (int)loadedVolumeMetadata[1] << " " << (int)loadedVolumeMetadata[2] << " " << (int)loadedVolumeMetadata[3] << endl;

	//Finding first available sector
	uint32_t firstAvailableSector =
		(loadedVolumeMetadata[0] << 24) |
		(loadedVolumeMetadata[1] << 16) |
		(loadedVolumeMetadata[2] << 8) |
		(loadedVolumeMetadata[3]);
	cout << "First available sector : " << firstAvailableSector << endl;

	//Checking if we have enough space left
	uint32_t maxAvailableSectors = UINT32_MAX - firstAvailableSector;
	uint32_t sectorsNeeded = static_cast<uint32_t>((filesystem::file_size(args[0]) + sectorSize - 1) / sectorSize);
	if (sectorsNeeded > maxAvailableSectors) {
		cout << "Not enough space available in this volume. Consider creating a new volume." << endl;
		return;
	}

	//Reading and encrypting each block
	ifstream targetFile(args[0], ios::binary);
	fstream volume(loadedVolumePath, ios::binary | std::ios::in | std::ios::out);
	vector<unsigned char> buffer(sectorSize);

	volume.seekp(volumeMetadataSize + (firstAvailableSector)*sectorSize);

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
	for (int i = 0; i < bytesForSectorCount; i++) { //TO FIX RIGHT THIS INSTANCE
		loadedVolumeMetadata[i] = (nextAvailableSector >> (8 * (bytesForSectorCount - 1 - i))) & 0xFF;
		newSectorWrite[i] = (nextAvailableSector >> (8 * (bytesForSectorCount - 1 - i))) & 0xFF;
		cout << "TEMP : Available Section Metadata : " << i << " " << (int)loadedVolumeMetadata[i] << endl;
	}

	cout << "New Sector Write : " << newSectorWrite << endl;

	volume.write(reinterpret_cast<char*>(newSectorWrite), bytesForSectorCount);

	//Adding the file data to the metadata
	//I think we need to use 4 bytes for each section code 
	
	//Finding the first available char
	uint32_t firstFreeCharPos = 0;

	for (uint32_t i = bytesForSectorCount; i < volumeMetadataSize; i++) {
		if (loadedVolumeMetadata[i] == 0) {
			firstFreeCharPos = i;

			cout << "First Free Char Pos Check" << hex << (int)loadedVolumeMetadata[i] << " " << (int)loadedVolumeMetadata[i + 1] << " " << (int)loadedVolumeMetadata[i + 2] << " " << (int)loadedVolumeMetadata[i + 3] << dec << endl;

			break;
		}
	}

	firstFreeCharPos += chacha20NonceSize;

	cout << "TEMP : firstFreeCharPos " << firstFreeCharPos << endl;

	volume.seekp(firstFreeCharPos);

	string filename = fs::path(args[0]).filename().string();

	cout << "Filename : " << filename << endl;

	//Padding string name with 0xFF - this should work because filename should be ASCII
	while(filename.length() < maxFileLengthName) filename += 0xFF;
	
	vector <unsigned char> newSectorDataToWrite(bytesForSectorCount * 2 + filename.size());

	cout << dec << endl;

	for (int i = firstFreeCharPos; i < firstFreeCharPos + bytesForSectorCount; i++) {
		loadedVolumeMetadata[i] = (firstAvailableSector >> (8 * (bytesForSectorCount - 1 - i - firstFreeCharPos))) & 0xFF;
		newSectorDataToWrite[i - firstFreeCharPos] = (firstAvailableSector >> (8 * (bytesForSectorCount - 1 - i - firstFreeCharPos))) & 0xFF;
	}

	for (int i = firstFreeCharPos + bytesForSectorCount; i < firstFreeCharPos + 2 * bytesForSectorCount; i++) {
		loadedVolumeMetadata[i] = (sectorsNeeded >> (8 * (bytesForSectorCount - 1 - i - firstFreeCharPos))) & 0xFF;
		newSectorDataToWrite[i - firstFreeCharPos] = (sectorsNeeded >> (8 * (bytesForSectorCount - 1 - i - firstFreeCharPos))) & 0xFF;;
	}

	uint16_t counter = firstFreeCharPos + 2* bytesForSectorCount;

	for (char character : filename) {
		loadedVolumeMetadata[counter] = character;
		newSectorDataToWrite[counter - firstFreeCharPos] = character;
		counter++;
	}
	
	//Visualising the new sector data to write
	cout << newSectorDataToWrite.size() << "New Sector Data To Write : " << hex;
	for (unsigned char sectorByte : newSectorDataToWrite) {
		cout << static_cast<int>(sectorByte);
	}
	cout << dec << endl;

	vector<unsigned char> encryptedNewSectorDataToWrite(newSectorDataToWrite.size());

	//Encrypting newSectorDataToWrite with ChaCha20
	if (usedAlgorithm == "ChaCha20") {
		crypto_stream_chacha20_xor(encryptedNewSectorDataToWrite.data(), newSectorDataToWrite.data(), newSectorDataToWrite.size(), loadedVolumeNonce, passwordHashed);
	}

	volume.write(reinterpret_cast<char*>(encryptedNewSectorDataToWrite.data()), encryptedNewSectorDataToWrite.size());


	volume.close();
	targetFile.close();

	cout << "TEMP : Volume metadata debugging : " << (int)loadedVolumeMetadata[0] << " " << (int)loadedVolumeMetadata[1] << " " << (int)loadedVolumeMetadata[2] << " " << (int)loadedVolumeMetadata[3] << endl;
}

void CommandCopyToVolume(vector<string> args) {
	/*Format of the file :
	0-12 : Nonce
	Volume metadata : 13-256^3
		0-3 - First available sector for writing
		4-131 - File entry index 1
			4-7 - First sector
			8 - 11 - Amount of sectors we use
			12-13 = Length of last sector
			14 - 131 - File name
	512 Byte sectors starting from 256^3
	*/

	ifstream targetFile(args[0], ios::binary);
	fstream volume(loadedVolumePath, ios::binary | std::ios::in | std::ios::out);

	//Step 1 - Find the first available sector we can write to
	uint32_t firstAvailableSector = (
		loadedVolumeMetadata[0] << 24 |
		loadedVolumeMetadata[1] << 16 |
		loadedVolumeMetadata[2] << 8 |
		loadedVolumeMetadata[3]
		);
	cout << "First available sector : " << dec << firstAvailableSector << endl;

	//Step 2 - Find the amount of sectors we need to use
	uint32_t amountOfSectorsNeeded = (filesystem::file_size(args[0]) + sectorSize - 1) / sectorSize; //Needed to round up
	cout << "Amount of Sectors Needed : " << amountOfSectorsNeeded << endl;

	uint32_t maxAvailableSectors = UINT32_MAX - firstAvailableSector;
	if (amountOfSectorsNeeded > maxAvailableSectors) {
		cout << "Not enough space in this volume - make a new volume";
		return;
	}

	//Step 3 - Find the first place we can make our entry
	uint32_t fileEntryFirstIndex = UINT32_MAX;
	for (int i = bytesForSectorCount; i < volumeMetadataSize - chacha20NonceSize; i += 2 * bytesForSectorCount + lengthBytes + maxFileLengthName) {

		//Checking if the first 2*bytesForSectorCount slots are all 0 - if they are we can use this slot, else we go to the next slot
		if (all_of(loadedVolumeMetadata + i, loadedVolumeMetadata + i + 2 * bytesForSectorCount, [](unsigned char c) { return c == 0; })) { fileEntryFirstIndex = i; break; }
	}

	if (fileEntryFirstIndex == UINT32_MAX) {
		cout << "Volume Metadata Full";
		return;
	}

	cout << "File Entry First Index : " << fileEntryFirstIndex << endl;

	//Step 4 - create and write the entry
	//We need to encrypt this whole entry
	vector<unsigned char> unencryptedFileIndexEntry(2 * bytesForSectorCount + lengthBytes + maxFileLengthName, 0);

	//Passing in the first sector we use
	unencryptedFileIndexEntry[0] = (firstAvailableSector >> 24) & 0xFF; //We do the & to snip the first 0s
	unencryptedFileIndexEntry[1] = (firstAvailableSector >> 16) & 0xFF;
	unencryptedFileIndexEntry[2] = (firstAvailableSector >> 8) & 0xFF;
	unencryptedFileIndexEntry[3] = (firstAvailableSector) & 0xFF;

	//Passing in the amount of sectors we use
	unencryptedFileIndexEntry[4] = (amountOfSectorsNeeded >> 24) & 0xFF; //We do the & to snip the first 0s
	unencryptedFileIndexEntry[5] = (amountOfSectorsNeeded >> 16) & 0xFF;
	unencryptedFileIndexEntry[6] = (amountOfSectorsNeeded >> 8) & 0xFF;
	unencryptedFileIndexEntry[7] = (amountOfSectorsNeeded) & 0xFF;

	//Passing in the length of the last sector
	uint16_t lengthOfLastSector = filesystem::file_size(args[0]) % 512;
	unencryptedFileIndexEntry[8] = (lengthOfLastSector >> 8) & 0xFF;
	unencryptedFileIndexEntry[9] = (lengthOfLastSector) & 0xFF;


	//Getting the file name and left-justifying it with 0xFF
	string filename = fs::path(args[0]).filename().string();
	cout << "Filename : " << filename << endl;
	while (filename.length() < maxFileLengthName) filename += 0xFF;

	//Setting the rest of the vector to the filename
	for (int i = 0; i < maxFileLengthName; i++) {
		unencryptedFileIndexEntry[2 * bytesForSectorCount + lengthBytes + i] = filename[i];
	}

	//Encrypting the entry
	vector<unsigned char> encryptedFileIndexEntry(2 * bytesForSectorCount + lengthBytes + maxFileLengthName, 0);
	uint32_t chaCha20Counter = (fileEntryFirstIndex - 4) / (2 * bytesForSectorCount + lengthBytes + maxFileLengthName);
	cout << "ChaCha20Counter : " << chaCha20Counter << endl;
	crypto_stream_chacha20_xor_ic(encryptedFileIndexEntry.data(), unencryptedFileIndexEntry.data(), unencryptedFileIndexEntry.size(), loadedVolumeNonce, chaCha20Counter, passwordHashed);

	//Writing the entry
	volume.seekp(chacha20NonceSize + fileEntryFirstIndex);
	volume.write(reinterpret_cast<char*>(encryptedFileIndexEntry.data()), encryptedFileIndexEntry.size());

	//Step 5 - Write the actual data
	volume.seekp(chacha20NonceSize + volumeMetadataSize + firstAvailableSector * sectorSize);
	vector<unsigned char> buffer(sectorSize, 0);
	vector<unsigned char> encryptedBuffer(sectorSize, 0);

	for (int i = firstAvailableSector; i < firstAvailableSector + amountOfSectorsNeeded; i++) {
		targetFile.read(reinterpret_cast<char*>(buffer.data()), sectorSize);

		if (targetFile.gcount() < sectorSize) {
			//Padding
			for (int j = targetFile.gcount(); j < sectorSize; j++) buffer[j] = 0xFF;
		}

		crypto_stream_chacha20_xor_ic(encryptedBuffer.data(), buffer.data(), buffer.size(), loadedVolumeNonce, UINT32_MAX + i, passwordHashed);
		volume.write(reinterpret_cast<char*>(encryptedBuffer.data()), sectorSize);
	}

	//Step 6 - Reupdating the first available sector
	uint32_t newFirstAvailableSector = firstAvailableSector + amountOfSectorsNeeded;
	volume.seekp(chacha20NonceSize);
	unsigned char newFirstAvailableSectorArr[4] = { 0 };
	newFirstAvailableSectorArr[0] = (newFirstAvailableSector >> 24) & 0xFF;
	newFirstAvailableSectorArr[1] = (newFirstAvailableSector >> 16) & 0xFF;
	newFirstAvailableSectorArr[2] = (newFirstAvailableSector >> 8) & 0xFF;
	newFirstAvailableSectorArr[3] = (newFirstAvailableSector) & 0xFF;

	volume.write(reinterpret_cast<char*>(newFirstAvailableSectorArr), 4);


	//Step 7 - update the metadata with our changes
	for (int i = 0; i < unencryptedFileIndexEntry.size(); i++) {
		loadedVolumeMetadata[fileEntryFirstIndex + i] = unencryptedFileIndexEntry[i];
	}

	loadedVolumeMetadata[0] = (newFirstAvailableSector >> 24) & 0xFF;
	loadedVolumeMetadata[1] = (newFirstAvailableSector >> 16) & 0xFF;
	loadedVolumeMetadata[2] = (newFirstAvailableSector >> 8) & 0xFF;
	loadedVolumeMetadata[3] = (newFirstAvailableSector) & 0xFF;
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

int main(int argc, char* argv[]){
	//Variables
	//string input;

	QApplication app(argc, argv);
	
	QMainWindow mainWindow;
	mainWindow.setWindowTitle("Cryptid");
	mainWindow.resize(600, 400); // Initial size

	//qDebug() << "exists:" << QFile::exists(":/images/icon.png");
	//qDebug() << "null:" << QIcon(":/images/icon.png").isNull();

	app.setWindowIcon(QIcon(":/images/icon.png"));

	QFile file(":/styles/style.qss");
	if (file.open(QFile::ReadOnly | QFile::Text)) {
		QString style = QString::fromUtf8(file.readAll());
		app.setStyleSheet(style);
	}

	// Create a central widget and a layout
	QWidget* centralWidget = new QWidget(&mainWindow);
	QVBoxLayout* layout = new QVBoxLayout(centralWidget);

	QPushButton* loadVolumeBtn = new QPushButton("Load Volume");
	QPushButton* createVolumeBtn= new QPushButton("Create Volume");
	QPushButton* volumeDetailsBtn = new QPushButton("Volume Details");
	QPushButton* addFileBtn = new QPushButton("Add Files To Volume");

	vector <QPushButton*> btns = {loadVolumeBtn, createVolumeBtn, volumeDetailsBtn, addFileBtn};

	for (QPushButton* btn : btns)
	{
		btn->setMinimumSize(100, 40); // button won’t shrink below this
		btn->setMaximumSize(200, 60); // button won’t grow beyond this
		layout->addWidget(btn);           // Add button to layout
		layout->setAlignment(btn, Qt::AlignCenter); // Center it
	}

	QLabel* label = new QLabel("Enter volume name:");
	QLineEdit* input = new QLineEdit();

	//LoadVolume
	QObject::connect(loadVolumeBtn, &QPushButton::clicked, [&]() {
		QString filePath = QFileDialog::getOpenFileName(
			nullptr,
			"Open Volume File",
			"",
			"Volume Files (*.cpd);;All Files (*.*)"
		);

		CommandLoadVolume(vector<string> {filePath.toStdString()});
		cout << "Loaded volume " << filePath.toStdString() << endl;
	});

	//Create Volume
	QObject::connect(createVolumeBtn, &QPushButton::clicked, [&]() {
		QString dir = QFileDialog::getExistingDirectory(
			nullptr,
			"Select Folder",
			"",
			QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
		);

		CommandCreateVolume(vector<string> {dir.toStdString(), (input->text()).toStdString()});
	});

	//Volume Details
	QObject::connect(volumeDetailsBtn, &QPushButton::clicked, [&]() {
		CommandVolumeDetails(vector<string> {});
	});

	//CopyFileToVolume
	QObject::connect(addFileBtn, &QPushButton::clicked, [&]() {
		QStringList files = QFileDialog::getOpenFileNames(
			nullptr,
			"Select Multiple Files",
			"",
			"All Files (*.*)"
		);

		for (QString file : files) {
			CommandCopyToVolume(vector<string> {file.toStdString()});
			cout << "Copied " << file.toStdString() << " to volume" << endl;
		}
	});

	layout->addWidget(label);
	layout->addWidget(input);

	mainWindow.setCentralWidget(centralWidget); // Set central widget
	mainWindow.show();

	return app.exec();
}