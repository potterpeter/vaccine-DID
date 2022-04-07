// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.10;

// Owner만 실행할 수 있는 컨트랙트
abstract contract OwnerHelper {
    address private owner;

    event OwnerTransferPropose(address indexed _from, address indexed _to);

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    // 함수 호출 시 owner = msg.sender로 자동 설정
    constructor() {
        owner = msg.sender;
    }

    // owner 권한을 가진 자가 다른 주소로 권한 위임
    function transferOwnership(address _to) public onlyOwner {
        require(_to != owner);
        require(_to != address(0x0));
        owner = _to;
        emit OwnerTransferPropose(owner, _to);
    }
}

// IssuerHelper는 Issuer을 추가 또는 삭제할 수 있다
// 그 기능은 onlyOwner로 제한되어 Owner만 제어 가능
abstract contract IssuerHelper is OwnerHelper {
    mapping(address => bool) public issuers;

    event AddIssuer(address indexed _issuer);
    event DelIssuer(address indexed _issuer);

    modifier onlyIssuer() {
        require(isIssuer(msg.sender) == true);
        _;
    }

    constructor() {
        issuers[msg.sender] = true;
    }

    function isIssuer(address _addr) public view returns (bool) {
        return issuers[_addr];
    }

    function addIssuer(address _addr) public onlyOwner returns (bool) {
        require(issuers[_addr] == false);
        issuers[_addr] = true;
        emit AddIssuer(_addr);
        return true;
    }

    function delIssuer(address _addr) public onlyOwner returns (bool) {
        require(issuers[_addr] == true);
        issuers[_addr] = false;
        emit DelIssuer(_addr);
        return true;
    }
}

// Credential 발행, 확인
contract CredentialBox is IssuerHelper {
    uint256 private idCount; // Credential이 한 주소에 하나씩만 발급받게 한다
    mapping(uint8 => string) private vaccineEnum; // 백신 종류
    mapping(uint8 => string) private statusEnum; // 접종 상태 (횟수)

    // VC를 구현하기 위한 구조체
    struct Credential {
        uint256 id; // index 순서 표기하는 idCount
        address issuer; // 발행자
        uint8 vaccineType; // 백신 증명서 타입
        uint8 statusType; //접종 상태 (횟수)
        string value; // 크리덴셜에 포함되어야 하는 암호화된 정보.
        // 중앙화된 서버에서 제공하는 신원, 서명 등이 JSON 형태로 저장됨
        uint256 createDate;
    }

    // 주소값으로 발급된 크리덴셜 확인
    mapping(address => Credential) private credentials;

    constructor() {
        idCount = 1;
        vaccineEnum[0] = "미접종 권고 대상자"; //약물알러지, 기저질환 등
        vaccineEnum[1] = "PFI"; //화이자
        vaccineEnum[2] = "JOH"; //얀센
        vaccineEnum[3] = "AST"; //아스트라제네카
        vaccineEnum[4] = "NOV"; //노바백스
        vaccineEnum[5] = "MOD"; //모더나
        statusEnum[0] = "미접종"; // 접종 상태 (횟수)
        statusEnum[1] = "1회차";
        statusEnum[2] = "2회차";
        statusEnum[3] = "3회차";
        statusEnum[4] = "4회차";
    }

    // claimCredential 함수로 Credential 발행
    function claimCredential(
        address _vaccineAddress,
        uint8 _vaccineType,
        uint8 _vaccineStatusType,
        string calldata _value
    ) public onlyIssuer returns (bool) {
        Credential storage credential = credentials[_vaccineAddress];

        // credential의 id가 0일 경우에만 함수 작동
        require(credential.id == 0);
        credential.id = idCount;
        credential.issuer = msg.sender;
        credential.vaccineType = _vaccineType;
        credential.statusType = 0;
        credential.value = _value;
        credential.createDate = block.timestamp; //block.timestamp를 활용해 크리덴셜을 클레임한 시간 저장

        idCount += 1;

        return true;
    }

    // getCredential 함수로 Credential을 발행한 주소에서 VC확인
    function getCredential(address _vaccineAddress)
        public
        view
        returns (Credential memory)
    {
        return credentials[_vaccineAddress];
    }

    function addVaccineType(uint8 _type, string calldata _value)
        public
        onlyIssuer
        returns (bool)
    {
        require(bytes(vaccineEnum[_type]).length == 0);
        vaccineEnum[_type] = _value;
        return true;
    }

    function getVaccineType(uint8 _type) public view returns (string memory) {
        return vaccineEnum[_type];
    }

    // bytes로 변환하여 길이로 String이 null인지 검사
    // 내부 statusEnum의 Type이 중복되는 타입이 존재하는지 검사
    function addStatusType(uint8 _type, string calldata _value)
        public
        onlyIssuer
        returns (bool)
    {
        require(bytes(statusEnum[_type]).length == 0);
        statusEnum[_type] = _value;
        return true;
    }

    function getStatusType(uint8 _type) public view returns (string memory) {
        return statusEnum[_type];
    }

    // 특정 사용자의 상태 변경
    // statusType의 값을 가져와 변경한다
    function changeStatus(address _vaccine, uint8 _type)
        public
        onlyIssuer
        returns (bool)
    {
        require(credentials[_vaccine].id != 0);
        require(bytes(statusEnum[_type]).length != 0);
        credentials[_vaccine].statusType = _type;
        return true;
    }
}
