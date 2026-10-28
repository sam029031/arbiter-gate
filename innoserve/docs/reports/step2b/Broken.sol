pragma solidity ^0.8.20;
contract Broken {
    function f() external { uint256 x = ; }
}
