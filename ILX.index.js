// Author: stpircsdahc
// Repository: https://github.com/StpircsDahc/f5sdk-mr_mut
/*
 ~ recommended reading
 https://devcentral.f5.com/articles/getting-started-with-irules-lx/getting-started-with-irules-lx-introduction-conceptual-overview-20409
 https://devcentral.f5.com/articles/getting-started-with-irules-lx-configuration-workflow-20410
 https://devcentral.f5.com/articles/getting-started-with-irules-lx/getting-started-with-irules-lx-part-3-coding-exception-handling-20411
 https://devcentral.f5.com/articles/getting-started-with-irules-lx/getting-started-with-irules-lx-part-4-npm-best-practices-20426
 https://devcentral.f5.com/articles/getting-started-with-irules-lx/getting-started-with-irules-lx-part-5-troubleshooting-20438
*/
// Import nodejs modules
var f5 = require('f5-nodejs');
var SSH = require('simple-ssh');
var ilx = new f5.ILXServer();

// Establish the RPC method
// Function parameters can be found in req.params().
ilx.addMethod('sshexec', function (req, res) {
  //console.log('ILX params: ' + req.params());
  //console.log('length: ' + req.params().length);

  // Convert the parameters to variables for future use
  if (req.params().length >= 1) {
    var user_action = req.params()[0];
    //console.log('user action is : ' +  user_action);
    var API_passwd = req.params()[1];

    //Establish the SSH session
    var ssh = new SSH({
      host: 'dahc-LE310', //could be an IP address otherwise needs to be resolvable via DNS or host record
      user: 'dahc',
      //pass: '<password>' // ~ used if not leveraging RSA keys for auth
      key: require('fs').readFileSync('./sshKEY')
    });
    //Establish commands wich will execute across the SSH session
    ssh.exec('python2 ./Projects/f5sdk-mr_mut/F5_demo.py', {
      args: [user_action, API_passwd], // send command line argugments as needed
      // Dump the output to stdout (which dumps to /var/log/ltm)
      out: function(stdout) {
        console.log(stdout);
      }
      //Start the SSH session
      }).start();
    //Send a response to the initiator (the iRule in this scenario)
    res.reply('yes');
  }
});
//Instruct the ILX server to begin listening for RPC calls
ilx.listen();
