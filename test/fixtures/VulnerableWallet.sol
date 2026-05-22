// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract VulnerableProxyWallet {
    mapping(address => uint256) public balances;
    address public owner;

    // 1. Vulnerability: Unprotected proxy initializer block
    // Missing 'initializer' or 'onlyOwner' modifiers allows anyone to hijack ownership.
    function initialize() public {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Zero balance");

        // 2. Vulnerability: Reentrancy state violation pattern
        // Sending ETH before setting the balance mapping to 0 allows an attacker to repeatedly call withdraw().
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;
    }

    function adminRescue(address target) public {
        // 3. Vulnerability: Dangerous origin authorization checks
        // Using tx.origin allows a phishing contract to pass this check if the owner interacts with it.
        require(tx.origin == owner, "Not authorized");
        
        // 4. Vulnerability: Inline Yul assembly bypasses validation checks
        // Arbitrary storage writes bypass typical Solidity compiler safety guardrails.
        assembly {
            let slot := 0
            sstore(slot, target)
        }
    }

    function closeWallet(address payable recipient) public {
        require(msg.sender == owner, "Not owner");
        
        // 5. Vulnerability: Deprecated state destruction execution route
        // selfdestruct is highly dangerous and completely destroys contract logic/traps funds.
        selfdestruct(recipient);
    }
}