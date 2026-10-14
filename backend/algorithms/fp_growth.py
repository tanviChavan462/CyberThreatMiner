"""
FP-Growth (Frequent Pattern Growth) algorithm implemented from first principles.
Constructs an FP-Tree (Frequent Pattern Tree) with header table links and
mines frequent itemsets without candidate generation via recursive conditional FP-trees.
"""
from typing import List, Set, Dict, FrozenSet, Tuple, Any, Optional
from collections import defaultdict


class FPNode:
    """Node in the Frequent Pattern Tree."""
    def __init__(self, item: Optional[str], count: int, parent: Optional['FPNode']):
        self.item = item
        self.count = count
        self.parent = parent
        self.children: Dict[str, 'FPNode'] = {}
        self.node_link: Optional['FPNode'] = None


class FPGrowthMiner:
    """Mines frequent itemsets using FP-Tree and conditional pattern bases."""

    def __init__(self):
        pass

    def mine(
        self,
        transactions: List[Set[str]],
        min_support: float,
        max_len: Optional[int] = None
    ) -> Dict[FrozenSet[str], float]:
        """
        Mines frequent itemsets with FP-Growth.

        Args:
            transactions: List of sets representing transaction baskets.
            min_support: Minimum support threshold in [0, 1].
            max_len: Optional maximum itemset length k.

        Returns:
            Dict mapping FrozenSet[item] to support float.
        """
        n_tx = len(transactions)
        if n_tx == 0:
            return {}

        min_count = min_support * n_tx

        # Step 1: Scan transactions to count 1-item frequencies
        item_counts: Dict[str, int] = defaultdict(int)
        for tx in transactions:
            for item in tx:
                item_counts[item] += 1

        # Keep only items meeting min_count
        frequent_items = {item: count for item, count in item_counts.items() if count >= min_count}
        if not frequent_items:
            return {}

        # Sort items in descending order of frequency (break ties alphabetically for determinism)
        rank_order = {item: (-count, item) for item, count in frequent_items.items()}

        # Step 2: Build FP-Tree
        root = FPNode(None, 0, None)
        header_table: Dict[str, Tuple[int, Optional[FPNode]]] = {
            item: (frequent_items[item], None) for item in frequent_items
        }

        # Header list of head pointers
        head_pointers: Dict[str, Optional[FPNode]] = {item: None for item in frequent_items}
        tail_pointers: Dict[str, Optional[FPNode]] = {item: None for item in frequent_items}

        for tx in transactions:
            # Filter and sort transaction items according to rank_order
            filtered_tx = [item for item in tx if item in frequent_items]
            filtered_tx.sort(key=lambda x: rank_order[x])

            # Insert into FP-Tree
            curr = root
            for item in filtered_tx:
                if item in curr.children:
                    curr.children[item].count += 1
                    curr = curr.children[item]
                else:
                    new_node = FPNode(item, 1, curr)
                    curr.children[item] = new_node
                    curr = new_node

                    # Link in header table chain
                    if tail_pointers[item] is None:
                        head_pointers[item] = new_node
                        tail_pointers[item] = new_node
                    else:
                        tail_pointers[item].node_link = new_node
                        tail_pointers[item] = new_node

        # Step 3: Mine tree recursively
        results: Dict[FrozenSet[str], float] = {}

        def find_prefix_path(leaf_node: FPNode) -> Tuple[List[str], int]:
            path: List[str] = []
            curr = leaf_node.parent
            while curr and curr.item is not None:
                path.append(curr.item)
                curr = curr.parent
            return path, leaf_node.count

        def mine_tree(
            head_nodes: Dict[str, Optional[FPNode]],
            prefix: FrozenSet[str],
            item_freqs: Dict[str, int]
        ):
            # Process items in ascending order of support
            sorted_items = sorted(item_freqs.keys(), key=lambda x: (item_freqs[x], x))

            for item in sorted_items:
                count = item_freqs[item]
                new_itemset = prefix | frozenset([item])

                if max_len is not None and len(new_itemset) > max_len:
                    continue

                results[new_itemset] = count / n_tx

                if max_len is not None and len(new_itemset) == max_len:
                    continue

                # Build conditional pattern base for `item`
                cond_patterns: List[Tuple[List[str], int]] = []
                node = head_nodes.get(item)
                while node:
                    path, path_count = find_prefix_path(node)
                    if path:
                        cond_patterns.append((path, path_count))
                    node = node.node_link

                # Count frequencies in conditional pattern base
                cond_item_counts: Dict[str, int] = defaultdict(int)
                for path, path_count in cond_patterns:
                    for p_item in path:
                        cond_item_counts[p_item] += path_count

                # Filter by min_count
                cond_freq_items = {
                    p_item: c for p_item, c in cond_item_counts.items() if c >= min_count
                }

                if not cond_freq_items:
                    continue

                # Build conditional FP-Tree
                cond_rank = {p_item: (-c, p_item) for p_item, c in cond_freq_items.items()}
                cond_root = FPNode(None, 0, None)
                cond_head: Dict[str, Optional[FPNode]] = {p: None for p in cond_freq_items}
                cond_tail: Dict[str, Optional[FPNode]] = {p: None for p in cond_freq_items}

                for path, path_count in cond_patterns:
                    filtered_path = [p for p in path if p in cond_freq_items]
                    filtered_path.sort(key=lambda x: cond_rank[x])

                    curr = cond_root
                    for p in filtered_path:
                        if p in curr.children:
                            curr.children[p].count += path_count
                            curr = curr.children[p]
                        else:
                            new_node = FPNode(p, path_count, curr)
                            curr.children[p] = new_node
                            curr = new_node

                            if cond_tail[p] is None:
                                cond_head[p] = new_node
                                cond_tail[p] = new_node
                            else:
                                cond_tail[p].node_link = new_node
                                cond_tail[p] = new_node

                # Recursive call
                mine_tree(cond_head, new_itemset, cond_freq_items)

        mine_tree(head_pointers, frozenset(), frequent_items)
        return results
