
function LogR(info)
{

  console.log('\x1B[31m',info+'\n')
}

function LogG(info)
{

  console.log('\x1B[32m',info+'\n')
}

function LogY(info)
{

  console.log('\x1B[33m',info)
}

function ConvertToString(object,type,language)
{

var strings=null;

if(language=='ObjC')
{
   switch(type){
  
   case "NSString":
   
       strings = new ObjC.Object(ptr(object)).toString()
       break;
      
   case "NSData":

       strings= object.bytes().readUtf8String(object.length())
       break;    

   case "NSMutableData":

       strings= object.bytes().readUtf8String(object.length()) 
       break;
      
   default:
    
    break;

     }

   }
  return strings;

}


function ConvertToObject(string,type,language)
{
  var object=null;

if(language=='ObjC' && string.length >0)
{
   switch(type){
  
   case "NSString":

        object=ObjC.classes.NSString.stringWithString_(string)

        break;
      
   case "NSData":

        var size = string.length;

        var address = Memory.alloc(size);

        Memory.writeUtf8String(address,string);
      
        object = ObjC.classes.NSData.dataWithBytes_length_(ptr(address), size);

        break;    

   case "NSMutableData":
        var size = string.length;

        var address = Memory.alloc(size);

        Memory.writeUtf8String(address,string);
      
        object = ObjC.classes.NSData.dataWithBytes_length_(ptr(address), size);
       break;
      
   default:
    
    break;

     }

   }
  return object

}

function ForwardData(data,name)
{
  var retval=null

  send({ 'type': 'frida','api':name,'payload': data });

  var op = recv('burp', function(value) {         
            retval=value.data
        });
  op.wait();

  return retval

}

var postData = ObjC.classes.SHEncrypt['- DecryptWithsecurityData:'];

// Intercept the method
Interceptor.attach(postData.implementation, {
  onEnter: function (args) {

    LogY('*DecryptWithsecurityData called \n' );
  },
  onLeave:function(retval){


   var string=ConvertToString(retval,'NSString','ObjC')  //convert NSString obeject to string 


   if (/^[\u0000-\u007f]*$/.test(string)==false)

  {
    string=escape(string)
  }
 
   var newString=ForwardData(strData,'SHDecrypt')    

   LogR("*RECV: \n"+unescape(newString))

  //var object=ConvertToObject(newString,'NSString','ObjC')       //convert string to NSString obeject

   //retval.replace(object)
 }

});


var receivedData = ObjC.classes.SHEncrypt['- EncryptWithdata:'];

Interceptor.attach(receivedData.implementation, {
  onEnter: function (args) {

  LogY('*EncryptWithdata called \n');

  var string=ConvertToString(args[2],'NSString','ObjC')     //convert NSString obeject to string 

  LogG("*SEND: \n"+string)

   if (/^[\u0000-\u007f]*$/.test(string)==false)            //check non-ascii charsets

  {
    string=escape(string)
  }
 
  var newString=ForwardData(string,'SHEncrypt')                // forward  string data to burp 

  LogR("*RECV: \n"+unescape(newString))

  var object=ConvertToObject(newString,'NSString','ObjC')       //convert string to NSString obeject

  args[2]=object                                             // replace arg
  
  },
  onLeave:function(retval){
    
 }


});


