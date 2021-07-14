#include <boost/program_options.hpp>
#include <iostream>

using namespace std;
namespace po = boost::program_options;

int main(int args, char** argv){

  try {

    po::options_description generic("Generic Options: ");
    generic.add_options()
      ("help", "help message")
      ("version,v", "print procedure version");

    int opt = 5;
    po::options_description ha("haha Options: ");
    ha.add_options()
      ("opt", po::value<int>(&opt)->default_value(10), "optimize value");

    po::options_description cmdline_options;
    cmdline_options.add(generic).add(ha);

    po::variables_map vm;
    po::store(po::parse_command_line(args, argv, cmdline_options), vm);
    po::notify(vm);

    if (vm.count("help")){
      cout << cmdline_options << endl;
      return 1;
    }
    cout << "vm opt = " << vm["opt"].as<int>() << endl;
    cout << "no opt = " << opt << endl;
  }
  catch(exception& e) {
  }
  catch(...) {
  }
  cout << "haha!" << endl;
  return 0;

}