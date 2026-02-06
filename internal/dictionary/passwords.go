package dictionary

// commonPasswordsList is the canonical list of well-known weak passwords
// compiled from public breach data (RockYou, LinkedIn, Adobe, etc.) and
// security research. Approximately 1 000 entries.
//
// All entries are stored lowercase; callers must lowercase before lookup.
//
//go:generate go test -run "TestPasswordList" -count=1 -v
var commonPasswordsList = []string{
	// ── Top-tier: appear in virtually every breach ──────────────────────
	"123456", "password", "12345678", "qwerty", "123456789",
	"12345", "1234", "111111", "1234567", "dragon",
	"123123", "baseball", "abc123", "football", "monkey",
	"letmein", "shadow", "master", "666666", "qwertyuiop",
	"123321", "mustang", "1234567890", "michael", "654321",
	"superman", "1qaz2wsx", "7777777", "121212", "000000",
	"qazwsx", "123qwe", "killer", "trustno1", "jordan",
	"jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
	"soccer", "harley", "batman", "andrew", "tigger",
	"sunshine", "iloveyou", "2000", "charlie", "robert",
	"thomas", "hockey", "ranger", "daniel", "starwars",
	"klaster", "112233", "george", "computer", "michelle",
	"jessica", "pepper", "1111", "zxcvbn", "555555",
	"11111111", "131313", "freedom", "777777", "pass",
	"maggie", "159753", "aaaaaa", "ginger", "princess",
	"joshua", "cheese", "amanda", "summer", "love",
	"ashley", "nicole", "chelsea", "biteme", "matthew",
	"access", "yankees", "987654321", "dallas", "austin",
	"thunder", "taylor", "matrix", "minecraft", "william",

	// ── Common password patterns ───────────────────────────────────────
	"password1", "password12", "password123", "password1234",
	"abc1234", "qwerty123", "qwerty1", "admin", "admin123",
	"root", "toor", "pass123", "pass1234", "changeme",
	"welcome", "welcome1", "welcome123", "login", "hello",
	"hello123", "test", "test123", "guest", "guest123",
	"master123", "letmein1", "iloveyou1", "monkey123",
	"dragon123", "shadow123", "sunshine1", "princess1",
	"passw0rd", "p@ssword", "p@ssw0rd", "pa$$word", "pa$$w0rd",

	// ── Keyboard patterns ──────────────────────────────────────────────
	"1q2w3e4r", "1q2w3e", "q1w2e3r4", "zaq1xsw2",
	"qweasdzxc", "1q2w3e4r5t", "qweasd",
	"asdf1234", "zxcv1234", "asdfghjkl", "poiuytrewq",
	"zxcvbnm123", "qwertyuiop123", "asdfghjkl123",
	"1234qwer", "qwer1234", "asdf", "zxcv",
	"qazwsxedc", "1qazxsw2", "zaq12wsx",

	// ── Numeric sequences ──────────────────────────────────────────────
	"102030", "010203", "252525", "101010", "999999",
	"123654", "456789", "789456", "147258369", "321654987",
	"159357", "951753", "135790", "246810", "369258",
	"112211", "334455", "998877", "556677", "223344",
	"100000", "111222", "222333", "333444", "444555",
	"555666", "666777", "777888", "888999", "999000",
	"010101", "020202", "030303", "040404", "050505",
	"060606", "070707", "080808", "090909", "123123123",
	"456456", "789789", "321321", "654654", "987987",
	"147147", "258258", "369369", "000001", "696969",

	// ── Common names ───────────────────────────────────────────────────
	"christopher", "anthony", "david", "james", "john",
	"joseph", "richard", "charles", "elizabeth", "samantha",
	"sarah", "hannah", "rachel", "stephanie", "lauren",
	"natalie", "alexis", "alyssa", "abigail", "olivia",
	"madison", "isabella", "sophia", "emma", "mia",
	"alexander", "benjamin", "nicholas", "jonathan", "jacob",
	"ethan", "nathan", "kevin", "jason", "brian",
	"brandon", "justin", "tyler", "aaron", "adam",
	"patrick", "ryan", "timothy", "eric", "steven",
	"mark", "scott", "paul", "kenneth", "jeffrey",
	"frank", "raymond", "gregory", "samuel", "henry",
	"peter", "douglas", "dennis", "jerry", "walter",
	"arthur", "albert", "gerald", "lawrence", "larry",
	"maria", "patricia", "linda", "barbara", "margaret",
	"susan", "dorothy", "betty", "sandra", "carol",
	"nancy", "deborah", "karen", "helen", "donna",
	"emily", "abby", "grace", "lily", "chloe",
	"victoria", "natasha", "rebecca", "christina", "heather",
	"angela", "diana", "crystal", "andrea", "amber",
	"vanessa", "tiffany", "brittany", "mercedes", "chelsea1",

	// ── Pop culture & entertainment ────────────────────────────────────
	"pokemon", "spiderman", "ironman", "avengers",
	"fortnite", "roblox", "mario", "zelda", "pikachu",
	"playstation", "xbox", "nintendo", "sonic", "pacman",
	"tetris", "simpsons", "familyguy", "southpark", "futurama",
	"marvel", "disney", "pixar", "frozen", "moana",
	"stargate", "startrek", "terminator", "avatar",
	"gandalf", "frodo", "legolas", "aragorn", "sauron",
	"hogwarts", "dumbledore", "voldemort", "snape", "hermione",
	"gryffindor", "slytherin", "naruto", "sasuke", "goku",
	"vegeta", "saiyan", "dragonball", "onepiece", "luffy",
	"deadpool", "wolverine", "magneto", "thanos", "hulk",
	"captain", "shield", "gotham", "joker", "arkham",

	// ── Sports ─────────────────────────────────────────────────────────
	"lakers", "cowboys", "eagles", "patriots",
	"ronaldo", "messi", "arsenal", "liverpool", "barcelona",
	"realmadrid", "juventus", "manchester", "bayern",
	"basketball", "tennis", "cricket", "rugby", "volleyball",
	"champion", "winner", "player", "goalkeeper", "striker",
	"premier", "league", "worldcup", "superbowl", "olympic",
	"marathon", "boxing", "wrestling", "karate", "judo",

	// ── Phrases & words ────────────────────────────────────────────────
	"fuckyou", "asshole", "fuck", "shit", "bitch",
	"whatever", "nothing", "secret", "internet", "google",
	"facebook", "twitter", "youtube", "amazon", "apple",
	"microsoft", "instagram", "tiktok", "snapchat", "reddit",
	"linkedin", "netflix", "spotify", "twitch", "discord",
	"iloveu", "loveyou", "mylove", "babe", "baby",
	"darling", "sweetheart", "honey", "angel", "cutie",
	"gorgeous", "beautiful", "handsome", "pretty", "lovely",
	"forever", "always", "together", "promise", "believe",
	"please", "thankyou", "sorry", "goodbye", "goodnight",
	"getout", "goaway", "shutup", "nomore", "enough",

	// ── Dates and years ────────────────────────────────────────────────
	"2001", "2002", "2003", "2004", "2005",
	"2006", "2007", "2008", "2009", "2010", "2011",
	"2012", "2013", "2014", "2015", "2016", "2017",
	"2018", "2019", "2020", "2021", "2022", "2023",
	"2024", "2025", "2026",
	"1212", "0101", "1001",
	"1990", "1991", "1992", "1993", "1994",
	"1995", "1996", "1997", "1998", "1999",

	// ── Animals ────────────────────────────────────────────────────────
	"tiger", "falcon", "eagle", "wolf", "panther",
	"cobra", "viper", "dragon1", "tiger1", "monkey1",
	"kitten", "puppy", "doggy", "kitty", "bunny",
	"horse", "stallion", "pony", "dolphin", "whale",
	"shark", "octopus", "butterfly", "phoenix", "unicorn",
	"bear", "lion", "leopard", "cheetah", "gorilla",
	"elephant", "giraffe", "penguin", "parrot", "turtle",
	"frog", "snake", "spider", "scorpion", "beetle",

	// ── Technology & computing ─────────────────────────────────────────
	"linux", "windows", "macos", "android", "iphone",
	"laptop", "desktop", "server", "network", "wifi",
	"bluetooth", "database", "python", "java", "html",
	"coding", "hacker", "cyber", "crypto", "bitcoin",
	"ethereum", "blockchain", "token", "wallet", "mining",
	"program", "software", "hardware", "system", "admin1",
	"root123", "administrator", "superuser", "sysadmin", "devops",
	"github", "gitlab", "docker", "cloud", "data",

	// ── Food & drink ───────────────────────────────────────────────────
	"chocolate", "coffee", "banana", "cherry", "lemon",
	"mango", "pizza", "burger", "candy", "cookie",
	"butter", "chicken", "steak", "sushi",
	"pasta", "noodle", "rice", "bread", "cake",
	"donut", "icecream", "cupcake", "brownie", "waffle",
	"pancake", "cereal", "bacon", "taco", "burrito",
	"vodka", "whiskey", "bourbon", "tequila", "champagne",
	"cocktail", "espresso", "latte", "smoothie", "juice",

	// ── Places ─────────────────────────────────────────────────────────
	"america", "london", "paris", "tokyo", "berlin",
	"moscow", "sydney", "toronto", "chicago", "boston",
	"newyork", "losangeles", "sanfrancisco", "seattle", "miami",
	"texas", "california", "florida", "hawaii", "alaska",
	"europe", "africa", "australia", "canada", "mexico",
	"brazil", "india", "china", "japan", "korea",

	// ── Music & culture ────────────────────────────────────────────────
	"guitar", "piano", "drums", "violin", "trumpet",
	"concert", "festival", "rocknroll", "hiphop", "reggae",
	"eminem", "drake", "beyonce", "rihanna", "madonna",
	"beatles", "acdc", "metallica", "nirvana", "queen",
	"bohemian", "stairway", "paradise", "heaven", "angels",

	// ── Nature & environment ───────────────────────────────────────────
	"flower", "garden", "river", "ocean", "mountain",
	"forest", "beach", "island", "castle", "tower",
	"sunrise", "sunset", "rainbow", "snowflake", "tornado",
	"volcano", "earthquake", "hurricane", "blizzard", "avalanche",
	"diamond", "emerald", "ruby", "sapphire",
	"pearl", "jade", "opal", "topaz",

	// ── Fantasy & mythology ────────────────────────────────────────────
	"wizard", "magic", "merlin", "excalibur", "camelot",
	"knight", "paladin", "sorcerer", "warlock", "shaman",
	"fairy", "goblin", "troll", "ogre", "demon",
	"vampire", "werewolf", "zombie", "ghost", "spirit",
	"warrior", "legend", "phantom", "samurai", "ninja",
	"pirate", "treasure", "quest", "adventure", "dungeon",
	"elven", "dwarf", "hobbit", "mordor", "rivendell",
	"druid", "necromancer", "oracle", "prophet", "titan",

	// ── Military & vehicles ────────────────────────────────────────────
	"marine", "soldier", "general", "colonel",
	"sergeant", "corporal", "private", "admiral", "commander",
	"sniper", "rifle", "pistol", "bullet", "weapon",
	"tank", "bomber", "fighter", "stealth", "missile",
	"corvette", "camaro", "mustang1", "ferrari", "porsche",
	"lamborghini", "bugatti", "mclaren", "tesla",
	"harley1", "yamaha", "kawasaki", "ducati", "suzuki",

	// ── Additional common passwords ────────────────────────────────────
	"blahblah", "passwd", "121314", "cacaca", "golden",
	"pepper1", "abcd1234", "sparky", "spartan", "silver",
	"midnight", "purple", "orange", "prince", "charlie1",
	"freedom1", "thunder1", "flower1", "sunshine123", "shadow1",
	"abc12345", "1234abcd", "pass12345", "hello1234", "welcome12",
	"iloveyou123", "monkey1234", "dragon1234", "soccer1",
	"baseball1", "football1", "hockey1", "batman1", "superman1",
	"trustno", "access1", "master1", "killer1", "hunter1",
	"ranger1", "buster1", "charlie123", "tigger1", "jordan1",
	"jennifer1", "jessica1", "michael1", "michelle1", "daniel1",
	"password!", "password1!", "12345!", "qwerty!", "admin!",
	"letmein!", "welcome!", "monkey!", "master!", "dragon!",
	"trustme", "openme", "opendoor", "opensesame", "letmepass",
	"enternow", "access123", "login123", "secure", "security",
	"safety", "protect", "privacy", "anonymous", "unknown",
	"nobody", "someone", "something", "anything", "everything",
	"number1", "thebest", "mybaby", "myangel", "mylife",
	"myworld", "myheart", "myself", "myname", "mydog",
	"mycat", "mycar", "myhouse", "myfamily", "myfriend",

	// ── Repeated patterns ──────────────────────────────────────────────
	"aaa", "bbb", "ccc", "ddd", "eee", "fff",
	"abcabc", "xyzxyz", "qweqwe", "asdasd", "zxczxc",
	"aabbcc", "aabb11", "aabb1122",
	"aaabbb", "111222333", "abcabcabc",
	"aaaa", "bbbb", "cccc", "dddd", "eeee",
	"aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee",
	"bbbbbb", "cccccc", "dddddd",

	// ── Short common PINs ──────────────────────────────────────────────
	"2222",
	"3333", "4444", "5555", "6666", "7777",
	"8888", "9999", "1357", "2468", "1379",
	"0852", "7890", "1230", "4560", "7891",
	"0987", "6543", "3210", "9876", "5432",

	// ── Leetspeak variants ─────────────────────────────────────────────
	"p4ssword", "p4ssw0rd", "h4cker", "h4x0r", "l33t",
	"3l1t3", "n00b", "r00t", "4dm1n", "m4st3r",
	"s3cur3", "s3cret", "pr1v4te", "l0g1n", "4cc3ss",

	// ── Miscellaneous common ───────────────────────────────────────────
	"password2", "password3", "letmein2", "welcome2", "qwerty12",
	"abc12", "xyz123", "asd123", "zxc123", "qwe123",
	"test1234", "temp1234", "user1234", "demo1234", "trial",
	"sample", "example", "default", "initial", "setup",
	"config", "backup", "recovery", "restore", "update",
	"install", "activate", "register", "signup", "login1",
}

// commonPasswords is the O(1) lookup set built from commonPasswordsList.
var commonPasswords = buildPasswordSet(commonPasswordsList)

// buildPasswordSet converts a slice of strings into a set (map) for
// O(1) membership testing. Duplicates are silently deduplicated.
func buildPasswordSet(passwords []string) map[string]bool {
	set := make(map[string]bool, len(passwords))
	for _, p := range passwords {
		set[p] = true
	}
	return set
}

// isCommonPassword reports whether password (must be lowercase) appears
// in the built-in common passwords set.
func isCommonPassword(password string) bool {
	return commonPasswords[password]
}

// isCommonPasswordIn reports whether password appears in the built-in set
// OR in the extra custom list. The custom list is checked via linear scan
// which is acceptable for typical blocklist sizes (< 10 000).
func isCommonPasswordIn(password string, custom []string) bool {
	if commonPasswords[password] {
		return true
	}
	for _, p := range custom {
		if p == password {
			return true
		}
	}
	return false
}
