
package de.breakpointsec.pushdown.fsm;

/*-
 * #%L
 * pushdown
 * %%
 * Copyright (C) 2019 Breakpoint Security GmbH
 * %%
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 * 
 * SPDX-License-Identifier: EPL-2.0
 * 
 * Copyright Breakpoint Security GmbH
 * #L%
 */

import com.google.common.base.Joiner;
import com.google.common.collect.*;
import de.breakpointsec.pushdown.IllegalTransitionException;
import de.breakpointsec.pushdown.weights.Semiring;

import java.util.*;

/**
 * A P-automaton that represents accepts a given configuration c = (L, S, W).
 *
 * The automaton is initially created by WPDS.waccept() and can be saturated using post* or pre*.
 *
 * Generic L refers to control locations of WPDS. Generic S refers to stack symbols of WPDS. Generic W refers to weights.
 *
 * @param <L>
 * @param <S>
 * @param <W>
 */
public abstract class WeightedAutomaton<L, S, W extends Semiring> {
	private Map<Transition<L, S>, W> transitionToWeights = new HashMap<>();
	private Set<Transition<L, S>> transitions = new HashSet<>();
	private Set<S> finalState = new HashSet<>();
	private final S initialState;
	protected Set<S> states = new HashSet<>();
	private final Multimap<S, Transition<L, S>> transitionsOutOf = HashMultimap.create();
	private final Multimap<S, Transition<L, S>> transitionsInto = HashMultimap.create();
	private WeightedAutomaton<L, S, W> initialAutomaton;
	private Set<S> unbalancedStates = new HashSet<>();
	private Map<Transition<L, S>, W> transitionsToFinalWeights = new HashMap<>();

	public WeightedAutomaton(S initialState) {
		this.initialState = initialState;
		this.unbalancedStates.add(initialState);
	}

	/**
	 * Implement this with specific instances of S and L.
	 *
	 * @param d
	 * @param loc
	 * @return
	 */
	public abstract S createState(S d, L loc);

	/**
	 * Implement this for a specific S.
	 * 
	 * @param d
	 * @return
	 */
	public abstract boolean isGeneratedState(S d);

	/**
	 * Implement this for a specific L.
	 *
	 * @return
	 */
	public abstract L epsilon();

	public Collection<Transition<L, S>> getTransitions() {
		return Sets.newHashSet(transitions);
	}

	public void addTransition(Transition<L, S> trans, W weight) {
		transitionsOutOf.get(trans.getStart()).add(trans);
		transitionsInto.get(trans.getTarget()).add(trans);
		states.add(trans.getTarget());
		states.add(trans.getStart());
		boolean added = transitions.add(trans);
		transitionToWeights.put(trans, weight);
	}

	public boolean addTransition(Transition<L, S> trans) {
		return combineWeightForTransition(trans, getOne());
	}

	public S getInitialState() {
		return initialState;
	}

	public Set<S> getFinalState() {
		return finalState;
	}

	public String toString() {
		String s = "PAutomaton\n";
		s += "\tInitialStates:" + initialState + "\n";
		s += "\tFinalStates:" + finalState + "\n";
		s += "\tWeightToTransitions:\n\t\t";
		s += Joiner.on("\n\t\t").join(transitionToWeights.entrySet());

		return s;
	}

	private String wrapIfInitialOrFinalState(S s) {
		return s.equals(initialState) ? "ENTRY: " + wrapFinalState(s) : wrapFinalState(s);
	}

	private String wrapFinalState(S s) {
		return finalState.contains(s) ? "TO: " + s + "" : s.toString();
	}

	public String toDotString() {
		return toDotString(new HashSet<>());
	}

	private String toDotString(Set<WeightedAutomaton<L, S, W>> visited) {
		if (!visited.add(this)) {
			return "NESTED loop: " + getInitialState();
		}
		String s = "digraph {\n";
		TreeSet<String> trans = new TreeSet<String>();
		for (S source : states) {
			Collection<Transition<L, S>> collection = transitionsOutOf.get(source);

			for (S target : states) {
				List<String> labels = new LinkedList<>();
				for (Transition<L, S> t : collection) {
					if (t.getTarget().equals(target)) {
						labels.add(escapeQuotes(t.getString().toString()) + " W: " + transitionToWeights.get(t));
					}
				}
				if (!labels.isEmpty()) {
					String v = "\t\"" + escapeQuotes(wrapIfInitialOrFinalState(source)) + "\"";
					v += " -> \"" + escapeQuotes(wrapIfInitialOrFinalState(target)) + "\"";
					v += "[label=\"" + String.join("\\n", labels) + "\"];\n";
					trans.add(v);
				}
			}

		}
		s += Joiner.on("").join(trans);
		s += "}\n";
		s += "Transitions: " + transitions.size() + "\n";

		return s;
	}

	private String escapeQuotes(String string) {
		return string.replace("\"", "");
	}

	public String toLabelGroupedDotString() {
		HashBasedTable<S, L, Collection<S>> groupedByTargetAndLabel = HashBasedTable.create();
		for (Transition<L, S> t : transitions) {
			Collection<S> collection = groupedByTargetAndLabel.get(t.getTarget(), t.getLabel());
			if (collection == null) {
				collection = new HashSet<>();
			}
			collection.add(t.getStart());
			groupedByTargetAndLabel.put(t.getTarget(), t.getLabel(), collection);
		}
		StringBuilder s = new StringBuilder("digraph {\n");
		for (S target : groupedByTargetAndLabel.rowKeySet()) {
			for (L label : groupedByTargetAndLabel.columnKeySet()) {
				Collection<S> source = groupedByTargetAndLabel.get(target, label);
				if (source == null) {
					continue;
				}
				s.append("\t\"");
				s.append(Joiner.on("\\n").join(source));
				s.append("\"");
				s.append(" -> \"");
				s.append(wrapIfInitialOrFinalState(target));
				s.append("\"");
				s.append("[label=\"");
				s.append(label);
				s.append("\"];\n");
			}
		}
		s.append("}\n");
		s.append("Transitions: ");
		s.append(transitions.size());
		s.append("\n");
		return s.toString();
	}

	/*
	 * public IRegEx<L> extractLanguage(S from) { PathExpressionComputer<S, L> expr = new PathExpressionComputer<>(this); IRegEx<L> res = null; for (S finalState :
	 * getFinalState()) { IRegEx<L> regEx = expr.getExpressionBetween(from, finalState); if (res == null) { res = regEx; } else { res = RegEx.<L>union(res, regEx); } } if
	 * (res == null) return new RegEx.EmptySet<L>(); return res; } public IRegEx<L> extractLanguage(S from, S to) { PathExpressionComputer<S, L> expr = new
	 * PathExpressionComputer<>(this); IRegEx<L> res = expr.getExpressionBetween(from, to); if (res == null) return new RegEx.EmptySet<L>(); return res; }
	 */

	public Set<S> getStates() {
		return states;
	}

	public Set<Transition<L, S>> getEdges() {
		Set<Transition<L, S>> trans = new HashSet<>();
		for (Transition<L, S> tran : transitions) {
			if (!tran.getLabel().equals(epsilon())) {
				trans.add(new Transition<L, S>(tran.getTarget(), tran.getLabel(), tran.getStart()));
			}
		}
		return trans;
	}

	public Set<S> getNodes() {
		return getStates();
	}

	public void setWeightForTransition(Transition<L, S> trans, W weight) throws IllegalTransitionException {
		if (weight == null)
			throw new IllegalArgumentException("Semiring must not be null!");
		if (trans.getStart().equals(trans.getTarget()) && trans.getLabel().equals(epsilon())) {
			throw new IllegalTransitionException("Epsilon loop in state " + trans.getStart().toString());
		}
		transitionsOutOf.get(trans.getStart()).add(trans);
		transitionsInto.get(trans.getTarget()).add(trans);
		states.add(trans.getTarget());
		states.add(trans.getStart());
		boolean added = transitions.add(trans);
		transitionToWeights.put(trans, weight);
	}

	public boolean combineWeightForTransition(Transition<L, S> trans, W weight) {
		if (weight == null)
			throw new IllegalArgumentException("Semiring must not be null!");
		if (trans.getStart().equals(trans.getTarget()) && trans.getLabel().equals(epsilon())) {
			return false;
		}
		transitionsOutOf.get(trans.getStart()).add(trans);
		transitionsInto.get(trans.getTarget()).add(trans);
		states.add(trans.getTarget());
		states.add(trans.getStart());
		boolean added = transitions.add(trans);
		W oldWeight = transitionToWeights.get(trans);
		W newWeight = (W) (oldWeight == null ? weight : oldWeight.combineWith(weight));
		if (!newWeight.equals(oldWeight)) {
			transitionToWeights.put(trans, newWeight);
			return true;
		}
		return added;
	}

	public W getWeightFor(Transition<L, S> trans) {
		return transitionToWeights.get(trans);
	}

	public void addFinalState(S state) {
		this.finalState.add(state);
	}

	public abstract W getZero();

	public abstract W getOne();

	public Collection<Transition<L, S>> getTransitionsOutOf(S s) {
		return this.transitionsOutOf.get(s);
	}

	public Collection<Transition<L, S>> getTransitionsInto(S s) {
		return this.transitionsInto.get(s);
	}

	/**
	 * Gets targets q of the relation p~γ~>q.
	 *
	 * @param start
	 * @param label
	 * @return
	 */
	public Collection<S> getTransitionTargetsIgnoringEpsilon(S start, L label) {
		Collection<S> results = new HashSet<>();
		LinkedList<Transition<L, S>> worklist = new LinkedList<>(this.transitionsOutOf.get(start));

		// Find transitions with epsilon or {@code label}.
		while (!worklist.isEmpty()) {
			Transition<L, S> t = worklist.pop();
			if (t.getLabel().equals(epsilon())) {
				worklist.addAll(this.transitionsOutOf.get(t.getTarget()));
			} else if (t.getLabel().equals(label)) {
				results.add(t.getTarget());
			}
		}

		// Expect at least one transition with {@code label}, otherwise quit
		if (results.isEmpty()) {
			return results;
		}

		// Append any epsilon transitions
		for (S s : results) {
			worklist.addAll(this.transitionsOutOf.get(s));
		}
		while (!worklist.isEmpty()) {
			Transition<L, S> t = worklist.pop();
			if (t.getLabel().equals(epsilon())) {
				results.add(t.getTarget());
				worklist.addAll(this.transitionsOutOf.get(t.getTarget()));
			}
		}

		return results;
	}

	public void addUnbalancedState(S state) {
		unbalancedStates.add(state);
	}

	public Map<Transition<L, S>, W> getTransitionsToFinalWeights() {
		for (S s : unbalancedStates) {
			updateFinalWeights(s, getOne());
		}
		return transitionsToFinalWeights;
	}

	private void updateFinalWeights(S s, W weight) {

		for (Transition<L, S> t : Lists.newArrayList(transitionsInto.get(s))) {
			W w = transitionToWeights.get(t);
			W newWeight = (W) weight.extendWith(w);
			W weightAtTarget = transitionsToFinalWeights.get(t);
			W newVal = (weightAtTarget == null ? newWeight : (W) weightAtTarget.combineWith(newWeight));
			transitionsToFinalWeights.put(t, newVal);
			if (isGeneratedState(t.getStart())) {
				updateFinalWeights(t.getStart(), newVal);
			}
		}
	}

	//    public IRegEx<L> toRegEx(S start, S end) {
	//        if (lastStates < states.size()) {
	//            pathExpressionComputer = new PathExpressionComputer<S, L>(this);
	//            lastStates = states.size();
	//        }
	//
	//        return RegEx.reverse(pathExpressionComputer.getExpressionBetween(end, start));
	//    }

	public boolean containsLoop() {
		// Performs a backward DFS
		HashSet<S> visited = new HashSet<>();
		LinkedList<S> worklist = new LinkedList<>();
		worklist.add(initialState);
		while (!worklist.isEmpty()) {
			S pop = worklist.pop();
			visited.add(pop);
			Collection<Transition<L, S>> inTrans = transitionsInto.get(pop);
			for (Transition<L, S> t : inTrans) {
				if (t.getLabel().equals(this.epsilon()))
					continue;
				if (!isGeneratedState(t.getStart()))
					continue;
				if (visited.contains(t.getStart())) {
					return true;
				}
				worklist.add(t.getStart());
			}
		}
		return false;
	}

	public Set<L> getLongestPath() {
		// Performs a backward DFS
		LinkedList<S> worklist = new LinkedList<>();
		worklist.add(initialState);
		Map<S, Set<L>> pathReachingD = new HashMap<>();
		while (!worklist.isEmpty()) {
			S pop = worklist.pop();
			Set<L> atCurr = getOrCreate(pathReachingD, pop);
			Collection<Transition<L, S>> inTrans = transitionsInto.get(pop);
			for (Transition<L, S> t : inTrans) {
				if (t.getLabel().equals(this.epsilon()))
					continue;
				S next = t.getStart();
				if (!isGeneratedState(next))
					continue;
				if (next.equals(pop))
					continue;
				Set<L> atNext = getOrCreate(pathReachingD, next);
				Set<L> newAtCurr = Sets.newHashSet(atCurr);
				if (newAtCurr.add(t.getLabel())) {
					boolean addAll = atNext.addAll(newAtCurr);
					if (addAll) {
						worklist.add(next);
					}
				}
			}
		}
		Set<L> longest = new HashSet<>();
		for (Set<L> l : pathReachingD.values()) {
			if (longest.size() < l.size()) {
				longest = l;
			}
		}
		return longest;
	}

	private Set<L> getOrCreate(Map<S, Set<L>> pathReachingD, S pop) {
		Set<L> collection = pathReachingD.get(pop);
		if (collection == null) {
			collection = new HashSet<>();
			pathReachingD.put(pop, collection);
		}
		return collection;
	}

}
