
#include <string>
#include <iostream>
using namespace std;



std::string cleanToField(std::string value) {
    std::string ans;
    
    int i = 0;
    while (i < value.size() && value[i] != '@') ++i;

    if (i == value.size()) return ans;

    while (i > 0 && value[i-1] != ' ' && value[i-1] != '<') --i;

    while (i < value.size() && value[i] != ' ' && value[i] != '>') ans += value[i++];

    return ans;
}


int main() {
    string value1 = "   Jackson Mears ";
    string value2 = "   <jacksonsmears@gmail.com>     ";
    string value3 = "jacksonsmears@gmail.com";
    string value4 = "jacksonsmears@gmail.com>";


    cout << cleanToField(value1) << endl;
    cout << cleanToField(value2) << endl;
    cout << cleanToField(value3) << endl;
    cout << cleanToField(value4) << endl;

    return 0;
}