#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <capstone/capstone.h>

using namespace std;
namespace fs = std::filesystem;

vector<unsigned char> readbin(string path){
    ifstream f(path, ios::binary);
    return vector<unsigned char>(
        (istreambuf_iterator<char>(f)),
        istreambuf_iterator<char>()
    );
}

bool is_prologue(cs_insn *i){

    if(string(i->mnemonic)=="push" &&
       string(i->op_str)=="rbp")
        return true;

    return false;
}

string pseudo(string m,string op){

    if(m=="mov") return op+";";
    if(m=="add") return op+";";
    if(m=="sub") return op+";";
    if(m=="ret") return "return;";

    return "// "+m+" "+op;
}

void extract_strings(vector<unsigned char>&data,string out){

    ofstream o(out+"/strings.txt");

    string s;

    for(auto c:data){

        if(isprint(c))
            s+=c;

        else{

            if(s.size()>4)
                o<<s<<"\n";

            s.clear();
        }
    }
}

int main(int argc,char**argv){

    if(argc<2){
        cout<<"mobilere <binary>\n";
        return 0;
    }

    string file=argv[1];
    string out=file+"_RE";

    fs::create_directories(out+"/functions");
    fs::create_directories(out+"/pseudocode");

    auto data=readbin(file);

    extract_strings(data,out);

    csh h;
    cs_open(CS_ARCH_X86,CS_MODE_64,&h);

    cs_insn *insn;

    size_t count=cs_disasm(
        h,data.data(),data.size(),0x1000,0,&insn
    );

    int func_id=-1;

    ofstream asmfile;
    ofstream cfile;
    ofstream callgraph(out+"/callgraph.txt");

    for(size_t i=0;i<count;i++){

        if(is_prologue(&insn[i])){

            func_id++;

            if(asmfile.is_open()) asmfile.close();
            if(cfile.is_open()) cfile.close();

            string fn=to_string(func_id);

            asmfile.open(out+"/functions/func_"+fn+".asm");
            cfile.open(out+"/pseudocode/func_"+fn+".c");
        }

        if(func_id<0) continue;

        asmfile<<hex<<insn[i].address
        <<" "
        <<insn[i].mnemonic<<" "
        <<insn[i].op_str<<"\n";

        cfile<<pseudo(insn[i].mnemonic,insn[i].op_str)<<"\n";

        if(string(insn[i].mnemonic)=="call"){

            callgraph<<"func_"
            <<func_id
            <<" -> "
            <<insn[i].op_str
            <<"\n";
        }
    }

    cs_free(insn,count);
    cs_close(&h);

    cout<<"analysis complete\n";
}