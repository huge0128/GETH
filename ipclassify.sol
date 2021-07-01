pragma solidity ^0.4.24;

contract SuspiciousIp {
    struct  IpAttributes {
        string ipaddress;
        uint timestamp;
        uint interval;
        uint Credibility;
        uint Threshold;
    }

    //uint  index = 0;
    //uint b_id = 0;     //blacklist_id
   // uint g_id = 0;    //graylist_id
    string state;
    //mapping  ipaddress => blacklist_id
    //mapping  ipaddress => graylist_id
    //mapping  IpAttributes => ipaddress

    mapping (uint => IpAttributes) IpList;
    string []  public IpAddrList;
    uint [] public IpThreshold;//IpNum
    mapping (uint => IpAttributes) blackList;
    uint [] public blackThreshold;//blackNum
    mapping (uint => IpAttributes) grayList;
    uint [] public grayThreshold;//grayNum


    function IpClassify(string ipAddress,uint timestamp,uint interval,uint Credibility,uint Threshold)  public returns(string,uint,uint b_id,uint g_id,string ) {
       IpAttributes memory ipattr= IpAttributes(ipAddress,timestamp,interval,Credibility,Threshold); 
       IpList[IpThreshold.length]=ipattr;
       //IpAddrList.push(ipAddress) -1;
       IpThreshold.push(Threshold) -1;
       //index ++;
// ===================================check if the ip is already in the stack=========================
       //for (uint i=0;i<index;i++){
       //    if (bytes (ipAddress).length == bytes (IpList[i].ipaddress).length && keccak256(ipAddress)==keccak256(IpList[i].ipaddress)) {
       //        bool state =false;
       //        break;
       //        return (ipattr.ipaddress,ipattr.Threshold,blacklist_id,graylist_id,state);
       //    }
       //} 
       if (IpThreshold.length == 1){
                if (ipattr.Credibility <= ipattr.Threshold){
                    blackList[b_id]=ipattr;
                    blackThreshold.push(Credibility) -1;
                    b_id ++;
                    state = "black";
               }
               else if (ipattr.Credibility > ipattr.Threshold){
                    grayList[g_id]=ipattr;
                    grayThreshold.push(Credibility) -1;
                    g_id ++;
                    state = "gray";
               }
               IpAddrList.push(ipAddress) -1;
               return (ipattr.ipaddress,ipattr.Threshold,b_id,g_id,state);
       }
       else {
           for (uint i=0;i<IpThreshold.length;i++){
              // if (bytes (ipAddress).length == bytes (IpList[i].ipaddress).length && keccak256(ipAddress)==keccak256(IpList[i].ipaddress)) {
               if (bytes (ipAddress).length == bytes (IpAddrList[i]).length && keccak256(ipAddress)==keccak256(IpAddrList[i])) {
                state ="false";
                return (ipattr.ipaddress,ipattr.Threshold,b_id,g_id,state);
                break;
                }
            }
//=========================if else :IP address classification according to the Credibility&Threshold=========================
            if (ipattr.Credibility <= ipattr.Threshold){
               blackList[b_id]=ipattr;
               blackThreshold.push(Credibility) -1;
               b_id ++;
               state = "black";
               IpAddrList.push(ipAddress) -1;
               }
           else if (ipattr.Credibility > ipattr.Threshold){
               grayList[g_id]=ipattr;
               grayThreshold.push(Credibility) -1;
               g_id ++;
               state = "gray";
               IpAddrList.push(ipAddress) -1;
               }
               return (ipattr.ipaddress,ipattr.Threshold,b_id,g_id,state);
           }
       
    }
    
    
    
    // get info about the ip;
    //function getiplist(uint _bid,uint _gid) view public returns (string black_ipaddress,uint black_timestamp,uint black_cred,string gray_ipaddress,uint gray_timestamp,uint gray_cred) {
        //return (blackList[_bid].ipaddress,blackList[_bid].timestamp,grayList[_gid].ipaddress,grayList[_gid].timestamp);
    //    return (blackList[_bid].ipaddress,blackList[_bid].timestamp,blackList[_bid].Credibility,grayList[_gid].ipaddress,grayList[_gid].timestamp,grayList[_gid].Credibility);
   // } 
    
    function getlastiplist() view public returns (string black_ipaddress,uint black_timestamp,uint black_cred,string gray_ipaddress,uint gray_timestamp,uint gray_cred) {
        //return (blackList[_bid].ipaddress,blackList[_bid].timestamp,grayList[_gid].ipaddress,grayList[_gid].timestamp);
        return (blackList[0].ipaddress,blackList[0].timestamp,blackList[0].Credibility,grayList[0].ipaddress,grayList[0].timestamp,grayList[0].Credibility);
    } 
    
//=================================just use the Threshold count IpNum ========================================
    
    //function getiplists() view public returns (uint[]) {
    //    return IpNum;
    //}
    
    //can use this function check the Thresholds
    function getThresholds() view public returns (uint[]) {
        return IpThreshold;
    }
        
// ==========================count ip ; count ip in blackList/grayList/IpList==================================
    //function countIPs() view public returns (uint IpNumber, uint blackNumber,uint grayNumber){
    //    return (IpThreshold.length,blackThreshold.length,grayThreshold.length);
    //}
    
    function countIPs() view public returns (uint ipNumber, uint blackNumber,uint grayNumber){
        return (IpAddrList.length,blackThreshold.length,grayThreshold.length);
    }
    // count ip in blackList
    //function countblackIPs() view public returns (uint){
    //    return blackNum.length;
    //}
    
    // count ip in grayList
    //function countgrayIPs() view public returns (uint) {
    //    return grayNum.length;
    //}

    
}
