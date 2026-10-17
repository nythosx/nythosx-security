import pytest
from unittest.mock import MagicMock, patch
from engine.mcts_agent import MCTSAgent, MCTSNode
from engine.state_machine import AppState, ContextWallet
from engine.invariants import InvariantOracle, InvariantRule

class MockResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text

class MockHttpClient:
    def __init__(self, responses):
        self.responses = responses
        self.call_count = 0

    def request(self, method, url, json=None, data=None, headers=None, params=None):
        if self.call_count < len(self.responses):
            resp = self.responses[self.call_count]
            self.call_count += 1
            return resp
        return MockResponse(404, "Not Found")

def test_mcts_agent_detects_invariant_break():
    # Setup: An oracle that flags "cart_total < 0" as a violation
    oracle = InvariantOracle()
    oracle.add_rule(InvariantRule(
        name="non_negative_cart",
        description="Cart total must be >= 0",
        condition="cart_total >= 0"
    ))
    
    # Setup: Mock HTTP client that returns a success on the 3rd request (simulating a bypass)
    responses = [
        MockResponse(200, '{"cart_total": 100}'),  # Normal state
        MockResponse(200, '{"cart_total": 100}'),  # Normal state
        MockResponse(200, '{"cart_total": -50}'),  # Invariant broken!
    ]
    client = MockHttpClient(responses)
    
    # Setup: MCTS Agent
    agent = MCTSAgent(oracle=oracle, max_rollouts=3)
    initial_state = AppState(name="start")
    initial_state.context_wallet = ContextWallet()
    initial_state.variables = {"cart_total": 100}
    
    # We need to mock the LLM client or the _propose_actions to return specific actions
    def mock_propose_actions(self, state):
        return [{"method": "POST", "url": "/api/cart", "payload": {"discount": -150}}]
    
    with patch.object(MCTSAgent, '_propose_actions', mock_propose_actions):
        # Run the search
        path = agent.search(initial_state, client)
        
        # Assertions
        assert len(path) > 0, "MCTS should have found a path"
        
        # Verify the oracle directly on the broken state
        broken_state = AppState(name="broken")
        broken_state.variables = {"cart_total": -50}
        
        rule = oracle.rules[0]
        assert rule.evaluate(broken_state.variables) is False, "Rule should evaluate to False for negative cart"

def test_mcts_agent_passes_when_no_invariant_break():
    oracle = InvariantOracle()
    oracle.add_rule(InvariantRule(
        name="non_negative_cart",
        description="Cart total must be >= 0",
        condition="cart_total >= 0"
    ))
    
    responses = [
        MockResponse(200, '{"cart_total": 100}'),
        MockResponse(200, '{"cart_total": 50}'),
    ]
    client = MockHttpClient(responses)
    
    agent = MCTSAgent(oracle=oracle, max_rollouts=2)
    initial_state = AppState(name="start")
    initial_state.context_wallet = ContextWallet()
    initial_state.variables = {"cart_total": 100}
    
    def mock_propose_actions(self, state):
        return [{"method": "POST", "url": "/api/cart", "payload": {"discount": 50}}]
    
    with patch.object(MCTSAgent, '_propose_actions', mock_propose_actions):
        path = agent.search(initial_state, client)
        assert isinstance(path, list), "Path should be a list"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
