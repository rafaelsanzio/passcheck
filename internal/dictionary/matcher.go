package dictionary

// acNode represents a node in the Aho-Corasick Trie.
type acNode struct {
	children map[rune]*acNode
	fail     *acNode
	output   []string
}

func newACNode() *acNode {
	return &acNode{
		children: make(map[rune]*acNode),
	}
}

// Matcher implements the Aho-Corasick string matching algorithm.
type Matcher struct {
	root *acNode
}

// NewMatcher constructs a new Aho-Corasick Machine given a list of words.
func NewMatcher(words []string) *Matcher {
	m := &Matcher{root: newACNode()}
	m.buildTrie(words)
	m.buildFailureLinks()
	return m
}

func (m *Matcher) buildTrie(words []string) {
	for _, word := range words {
		curr := m.root
		for _, char := range word {
			if curr.children[char] == nil {
				curr.children[char] = newACNode()
			}
			curr = curr.children[char]
		}
		curr.output = append(curr.output, word)
	}
}

func (m *Matcher) buildFailureLinks() {
	queue := []*acNode{}

	// Root's children fail to root and are pushed to the queue.
	for _, child := range m.root.children {
		child.fail = m.root
		queue = append(queue, child)
	}

	// BFS traversal
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for char, child := range curr.children {
			queue = append(queue, child)

			// Find failure link for the child
			failNode := curr.fail
			for failNode != nil && failNode.children[char] == nil {
				failNode = failNode.fail
			}

			if failNode == nil {
				child.fail = m.root
			} else {
				child.fail = failNode.children[char]
			}

			// Append outputs from the failure node
			if len(child.fail.output) > 0 {
				child.output = append(child.output, child.fail.output...)
			}
		}
	}
}

// FindAll returns all distinct matches of the vocabulary in the text.
// It searches in O(N) time where N is the length of the text.
// The text is assumed to be lowercase already (same as dictionary assumption).
func (m *Matcher) FindAll(text string) []string {
	var matches []string
	seen := make(map[string]bool)

	curr := m.root
	for _, char := range text {
		for curr != nil && curr != m.root && curr.children[char] == nil {
			curr = curr.fail
		}
		if curr.children[char] != nil {
			curr = curr.children[char]
		} else {
			curr = m.root
		}

		for _, word := range curr.output {
			if !seen[word] {
				seen[word] = true
				matches = append(matches, word)
			}
		}
	}

	return matches
}
