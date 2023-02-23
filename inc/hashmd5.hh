#ifndef HASHMD5_HH
#define HASHMD5_HH
#include <openssl/evp.h>
#include <bits/stdc++.h>
#include <algorithm>
#include <thread>
#include <unistd.h>
#include <csignal>

using std::string;

void bytes2md5(const char *data, int len, char *md5buf) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        const EVP_MD *md = EVP_md5();
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len, i;
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, data, len);
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_free(mdctx);
        for (i = 0; i < md_len; i++) {
                snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
        }
}

struct user{
        int id;
        string hash, mail, login;
        bool is_cracked;
};



class PassCrack
{
private:
        inline static int crackedcout=0;
        std::mutex mtx;
        std::condition_variable condition;

        std::vector<user> userdb;
        std::vector<string> worddb;
        std::vector<user> cracked;


        std::stop_source producer_source;
        std::stop_source consumer_source;
        
        static void sighup(int);
        
        void load_users(const string &userpath);
        void load_words(const string &dictionarypath);
        void check_hashdb(const string &word);

        void consumer(std::stop_token token);
        void producer0(std::stop_token token);
        void producer1(std::stop_token token);
        void producer2(std::stop_token token);
        void producer3(std::stop_token token);
        void producer4(std::stop_token token);
        void producer5(std::stop_token token);
public:
        void start();
};

void PassCrack::start(){
        std::signal(SIGHUP, PassCrack::sighup);
        string input;

        //Ladowanie bazy slow
        std::cout << "Podaj nazwe slownika: ";
        while (std::cin >> input){
                if (std::filesystem::exists(input)){
                        load_words(input);
                        break;
                }
                else
                        std::cout << "Plik nie istnieje!\n"; 
        }
        
        //Ladowanie bazy hasel po raz pierwszy
        std::cout << "Podaj baze hasel: ";
        while (std::cin >> input){
                if (std::filesystem::exists(input)){
                        load_users(input);
                        break;
                }
                else
                        std::cout << "Plik nie istnieje!\n"; 
        }



        std::unique_lock<std::mutex> lock(mtx);

        std::jthread c0(&PassCrack::consumer, this, consumer_source.get_token());
        std::jthread p0(&PassCrack::producer0, this, producer_source.get_token());
        std::jthread p1(&PassCrack::producer1, this, producer_source.get_token());
        std::jthread p2(&PassCrack::producer2, this, producer_source.get_token());
        std::jthread p3(&PassCrack::producer3, this, producer_source.get_token());
        std::jthread p4(&PassCrack::producer4, this, producer_source.get_token());
        std::jthread p5(&PassCrack::producer5, this, producer_source.get_token());

        lock.unlock();
        
        

        while (std::cin >> input){
                if(input == "stop"){
                        lock.lock();
                        producer_source.request_stop();
                        p0.join();
                        p1.join();
                        p2.join();
                        p3.join();
                        p4.join();
                        p5.join();
                        lock.unlock();
                        break;
                }
                else if (std::filesystem::exists(input)){     
                        lock.lock();

                        //Zatrzymanie watkow
                        producer_source.request_stop();
                        p0.join();
                        p1.join();
                        p2.join();
                        p3.join();
                        p4.join();
                        p5.join();
                
                        //reset tokenu
                        producer_source = std::stop_source();

                        //zaladowanie nowych hasel
                        userdb.clear();
                        load_users(input);

                        //Start nowych watkow
                        p0 = std::jthread(&PassCrack::producer0, this, producer_source.get_token());
                        p1 = std::jthread(&PassCrack::producer1, this, producer_source.get_token());
                        p2 = std::jthread(&PassCrack::producer2, this, producer_source.get_token());
                        p3 = std::jthread(&PassCrack::producer3, this, producer_source.get_token());
                        p4 = std::jthread(&PassCrack::producer4, this, producer_source.get_token());
                        p5 = std::jthread(&PassCrack::producer5, this, producer_source.get_token());
                        lock.unlock();
                }
                else
                        std::cout << "Plik nie istnieje!\n";    
        }

        lock.lock();
        consumer_source.request_stop();
        condition.notify_one();
        lock.unlock();
        c0.join();
}


void PassCrack::check_hashdb(const string &word){
        char hashword[32];
        
        bytes2md5(word.c_str(), word.size(), hashword);

        for(size_t i = 0; i < userdb.size(); ++i){
                if(!strcmp(userdb[i].hash.c_str(), hashword) && userdb[i].is_cracked == false){
                        std::unique_lock<std::mutex> lock(mtx);
                        userdb[i].is_cracked = true;    //to haslo jest zlamane, info dla innych producentow
                        cracked.push_back(userdb[i]);   //wrzucam na liste zlamanych juz
                        cracked.back().hash = word;     //zapisuje sobie haslo w tej liscie zlamanych
                        condition.notify_one();         //dzwonie na policje 997!
                        lock.unlock();
                }
        }
}


//////////////////
//Funkcje do glownej petli
//////////////////

void PassCrack::sighup(int){
        std::cout << "Zlamano juz: " << crackedcout << " hasel.\n";
}

void PassCrack::load_users(const string &userpath){
        user tmp;
        std::cout << "Otwieranie bazy hasel...\n";

        std::ifstream database(userpath);
        if(!database)
                throw std::invalid_argument("Nie udalo sie otworzyc pliki z baza danych uzytkownikow!\n");

        while(database >> tmp.id >> tmp.hash >> tmp.mail){
                getline(database, tmp.login);

                tmp.login.erase(std::remove_if(tmp.login.begin(), tmp.login.end(), ::isspace), tmp.login.end());
                
                tmp.is_cracked = false;
                userdb.push_back(tmp);
        }
        std::cout << "Wczytanie powiodlo sie!\n\n";
        database.close();
}

void PassCrack::load_words(const string &dictionarypath){
        string tmp;
        std::cout << "Otwieranie bazy slow...\n";

        std::ifstream database(dictionarypath);
        if(!database)
                throw std::invalid_argument("Nie udalo sie otworzyc slownika!\n");

        while(database >> tmp){
                worddb.push_back(tmp);
        }
        std::cout << "Wczytanie powiodlo sie!\n\n";
        database.close();
}


//////////////////
//KONSUMENT
//////////////////


void PassCrack::consumer(std::stop_token token){
        while(1){
                std::unique_lock<std::mutex> lock(mtx);
                condition.wait(lock);
                if(token.stop_requested()){
                        return;
                }
                crackedcout++;
                std::cout << crackedcout << ". Password for "<< cracked[crackedcout - 1].mail << " is " << cracked[crackedcout - 1].hash << "\n";
                lock.unlock();
        }
}


//////////////////
//PRODUCENCI
//////////////////


//word + word with num at end or front
void PassCrack::producer0(std::stop_token token){
        for(size_t i = 0; i < worddb.size(); ++i){

                //word
                check_hashdb(worddb[i]);

                //word+num and num+word
                for (int a = 0; a < 100; ++a){
                        if (token.stop_requested()){
                                return;
                        }
                        check_hashdb(worddb[i] + std::to_string(a));
                        check_hashdb(std::to_string(a) + worddb[i]);
                }
        }
}//2001n kombinacji 

//Word + Word with num at end or front
void PassCrack::producer1(std::stop_token token){
        string tmp;
        for(size_t i = 0; i < worddb.size(); ++i){

                //Word
                tmp = worddb[i];
                tmp[0] = toupper(tmp[0]);
                check_hashdb(tmp);

                //Word + num and num + Word
                for (int a = 0; a < 100; ++a){
                        if (token.stop_requested()){
                                return;
                        }
                        check_hashdb(tmp + std::to_string(a));
                        check_hashdb(std::to_string(a) + tmp);
                }
        }
}//201n kombinacji 

//WORD + WORD with num at end or front
void PassCrack::producer2(std::stop_token token){
        string tmp;
        for(size_t i = 0; i < worddb.size(); ++i){

                //WORD
                tmp = worddb[i];
                std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::toupper);
                check_hashdb(tmp);

                //WORD + num and num + WORD
                for (int a = 0; a < 100; ++a){
                        if (token.stop_requested()){
                                return;
                        }
                        check_hashdb(tmp + std::to_string(a));
                        check_hashdb(std::to_string(a) + tmp);
                }
        }
}//201n kombinacji 

//numA + word + numB
void PassCrack::producer3(std::stop_token token){
        for(size_t i = 0; i < worddb.size(); ++i){
                for (int a = 0; a < 50; ++a){
                        for (int b = 0; b < 50; ++b){
                                if (token.stop_requested()){
                                        return;
                                }

                                check_hashdb(std::to_string(a)+worddb[i]+std::to_string(b));
                        }
                }
        }
}//2500n kombinacji 

//numA + Word + numB
void PassCrack::producer4(std::stop_token token){
        string tmp;

        for(size_t i = 0; i < worddb.size(); ++i){
                tmp = worddb[i];
                tmp[0] = toupper(tmp[0]);
                for (int a = 0; a < 50; ++a){
                        for (int b = 0; b < 50; ++b){
                                if (token.stop_requested()){
                                        return;
                                }

                                check_hashdb(std::to_string(a)+tmp+std::to_string(b));
                        }
                }
        }
}//2500n kombinacji 

//word + word
void PassCrack::producer5(std::stop_token token){

        for(size_t i = 0; i < worddb.size(); ++i){
                for(size_t j = 0; j < worddb.size(); ++j){
                        if (token.stop_requested()){
                                return;
                        }
                        check_hashdb(worddb[i] + worddb[j]);
                }
        }
}//n^2 kombijacji

#endif