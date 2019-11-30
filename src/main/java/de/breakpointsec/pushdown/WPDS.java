
package de.breakpointsec.pushdown;

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
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import de.breakpointsec.pushdown.fsm.Transition;
import de.breakpointsec.pushdown.fsm.WeightedAutomaton;
import de.breakpointsec.pushdown.rules.NormalRule;
import de.breakpointsec.pushdown.rules.PopRule;
import de.breakpointsec.pushdown.rules.PushRule;
import de.breakpointsec.pushdown.rules.Rule;
import de.breakpointsec.pushdown.weights.Semiring;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Implementation of a Weighted Pushdown System.
 *
 * This is the main class you may want to use for constructing a WPDS.
 *
 * @param <L> Control location
 * @param <S> State
 * @param <W> Semiring
 */
public abstract class WPDS<L, S, W extends Semiring> {

	protected final Set<PushRule<L, S, W>> pushRules = Sets.newHashSet();
	protected final Set<PopRule<L, S, W>> popRules = Sets.newHashSet();
	protected Set<S> states = Sets.newHashSet();
	protected final Set<NormalRule<L, S, W>> normalRules = Sets.newHashSet();
	private final Multimap<S, Transition<L, S>> transitionsInto = HashMultimap.create();

	public boolean addRule(Rule<L, S, W> rule) {
		return addRuleInternal(rule);
	}

	private boolean addRuleInternal(Rule<L, S, W> rule) {
		if (rule instanceof PushRule)
			return pushRules.add((PushRule) rule);
		else if (rule instanceof PopRule)
			return popRules.add((PopRule) rule);
		else if (rule instanceof NormalRule)
			return normalRules.add((NormalRule) rule);
		throw new RuntimeException("Try to add a rule of wrong type");
	}

	public Set<NormalRule<L, S, W>> getNormalRules() {
		return normalRules;
	}

	public Set<PopRule<L, S, W>> getPopRules() {
		return popRules;
	}

	public Set<PushRule<L, S, W>> getPushRules() {
		return pushRules;
	}

	public Set<Rule<L, S, W>> getAllRules() {
		Set<Rule<L, S, W>> rules = Sets.newHashSet();
		rules.addAll(normalRules);
		rules.addAll(popRules);
		rules.addAll(pushRules);
		return rules;
	}

	@Deprecated
	public Set<Rule<L, S, W>> getRulesStarting(S start, L string) {
		Set<Rule<L, S, W>> result = new HashSet<>();
		getRulesStartingWithinSet(start, string, popRules, result);
		getRulesStartingWithinSet(start, string, normalRules, result);
		getRulesStartingWithinSet(start, string, pushRules, result);
		return result;
	}

	@Deprecated
	private void getRulesStartingWithinSet(S start, L string, Set<? extends Rule<L, S, W>> rules,
			Set<Rule<L, S, W>> res) {
		for (Rule<L, S, W> r : rules) {
			if (r.getS1().equals(start) && r.getL1().equals(string)) {
				res.add(r);
			}
		}
	}

	public Set<NormalRule<L, S, W>> getNormalRulesEnding(S start, L string) {
		Set<NormalRule<L, S, W>> allRules = getNormalRules();
		Set<NormalRule<L, S, W>> result = new HashSet<>();
		for (NormalRule<L, S, W> r : allRules) {
			if (r.getS2().equals(start) && r.getL2().equals(string))
				result.add(r);
		}
		return result;
	}

	public Set<PushRule<L, S, W>> getPushRulesEnding(S start, L string) {
		Set<PushRule<L, S, W>> allRules = getPushRules();
		Set<PushRule<L, S, W>> result = new HashSet<>();
		for (PushRule<L, S, W> r : allRules) {
			if (r.getS2().equals(start) && r.getL2().equals(string))
				result.add(r);
		}
		return result;
	}

	@Deprecated
	public Set<S> getStates() {
		Set<S> states = Sets.newHashSet();
		for (Rule<L, S, W> r : getAllRules()) {
			states.add(r.getS1());
			states.add(r.getS2());
		}
		return states;
	}

	protected boolean updatePostStar(Transition<L, S> t, W w, Rule rule, final WeightedAutomaton<L, S, W> fa, final LinkedList<Transition<L, S>> worklist)
			throws IllegalTransitionException {
		if (!fa.getTransitions().contains(t)) {
			fa.addTransition(t, null);
		}
		W oldWeight = fa.getWeightFor(t);
		W newWeight = (oldWeight == null) ? w : (W) oldWeight.combineWith(w);
		boolean changed = !newWeight.equals(oldWeight);
		if (changed) {
			fa.setWeightForTransition(t, newWeight);
			worklist.add(t);
		}
		return changed;
	}

	/**
	 * Implementation of post*, according to Reps, T., Schwoon, S., Jha, S., & Melski, D. (2005). Weighted pushdown systems and their application to interprocedural
	 * dataflow analysis. In Science of Computer Programming. https://doi.org/10.1016/j.scico.2005.02.009 Algorithm 3, Figure 17
	 *
	 * @param fa initial P-automaton
	 */
	public void poststar(WeightedAutomaton<L, S, W> fa) throws IllegalTransitionException {
		// Phase 1: For each pair <p', γ'> such that pds contains at least one rule of the form <p', γ'γ''> (i.e., a push rule), add a new state p'_γ''.
		Map<PushRule<L, S, W>, S> generatedStates = new HashMap<>();
		for (PushRule<L, S, W> rule : getPushRules()) {
			final S p = rule.getS2();
			final L gammaPrime = rule.getL2();
			final S irState = fa.createState(p, gammaPrime);
			final L transitionLabel = rule.getCallSite();
			generatedStates.put(rule, irState);
		}

		// Phase 2 (saturation)
		LinkedList<Transition<L, S>> worklist = Lists.newLinkedList(fa.getTransitions());
		while (!worklist.isEmpty()) {
			Transition<L, S> t = worklist.pop();

			//Transitive pops
			if (t.getLabel().equals(epsilon())) {

				for (Transition<L, S> transPrime : fa.getTransitionsOutOf(t.getTarget())) {
					Transition<L, S> newTrans = new Transition<>(t.getStart(), transPrime.getLabel(), transPrime.getTarget());
					W newWeight = (W) fa.getWeightFor(transPrime).extendWith(fa.getWeightFor(t));
					updatePostStar(newTrans, newWeight, null, fa, worklist);
				}

			} else {

				// Pop rules
				for (PopRule<L, S, W> rule : getPopRules()) {
					if (rule.getS1().equals(t.getStart()) && rule.getL1().equals(t.getLabel())) {
						Transition<L, S> newTrans = new Transition<L, S>(rule.getS2(), epsilon(), t.getTarget());
						W newWeight = (W) fa.getWeightFor(t).extendWith(rule.getWeight());
						updatePostStar(newTrans, newWeight, rule, fa, worklist);
					}
				}

				// Normal rules
				for (NormalRule<L, S, W> rule : getNormalRules()) {
					if (rule.getS1().equals(t.getStart()) && rule.getL1().equals(t.getLabel())) {
						Transition<L, S> newTrans = new Transition<L, S>(rule.getS2(), rule.getL2(), t.getTarget());
						W newWeight = (W) fa.getWeightFor(t).extendWith(rule.getWeight());
						updatePostStar(newTrans, newWeight, rule, fa, worklist);
					}
				}

				// Push rules
				for (PushRule<L, S, W> rule : getPushRules()) {
					if (rule.getS1().equals(t.getStart()) && rule.getL1().equals(t.getLabel())) {

						S irState = generatedStates.get(rule);
						if (irState == null) {
							System.out.println("UNEXPECTED: No generated state found for rule " + rule.toString());
						}
						Transition<L, S> newTrans = new Transition<L, S>(rule.getS2(), rule.getL2(), irState);
						updatePostStar(newTrans, fa.getOne(), rule, fa, worklist);

						Transition<L, S> newTrans2 = new Transition<L, S>(irState, rule.getCallSite(), t.getTarget());
						W newWeight2 = (W) fa.getWeightFor(t).extendWith(rule.getWeight());
						boolean changed = updatePostStar(newTrans2, newWeight2, rule, fa, worklist);
						if (changed) {
							Set<Transition<L, S>> tPrimes = fa.getTransitionsInto(irState)
									.stream()
									.filter(trans -> trans.getLabel().equals(fa.epsilon()) && trans.getTarget().equals(irState))
									.collect(Collectors.toSet());
							for (Transition<L, S> tPrime : tPrimes) {
								updatePostStar(new Transition<L, S>(tPrime.getStart(), rule.getCallSite(), t.getTarget()),
									(W) newWeight2.extendWith(fa.getWeightFor(tPrime)), rule, fa, worklist);
							}
						}

					}
				}
			}
		}

	}

	/**
	 * pre*-saturation algorithm returns a finite automaton representing the backwards reachable set of the configuration represented by the initial automaton.
	 *
	 * Implementation according to Reps, T., Lal, A., & Kidd, N. (2007). Program Analysis Using Weighted Pushdown Systems, 23–51.
	 * https://doi.org/10.1007/978-3-540-77050-3_4 Algorithm 1 (Figure 9).
	 *
	 * @param fa initial P-automaton
	 * @return
	 */
	public WeightedAutomaton<L, S, W> prestar(WeightedAutomaton<L, S, W> fa) throws IllegalTransitionException {
		LinkedList<Transition<L, S>> worklist = Lists.newLinkedList(fa.getTransitions());
		for (Transition<L, S> trans : Sets.newHashSet(fa.getTransitions())) {
			W one = fa.getOne();
			fa.combineWeightForTransition(trans, one);
		}

		// Initialize with pop rules.
		for (PopRule<L, S, W> r : this.getPopRules()) {
			updatePrestar(worklist, new Transition<>(r.getS1(), r.getL1(), r.getS2()), r.getWeight(), fa);
		}

		while (!worklist.isEmpty()) {
			Transition<L, S> t = worklist.pop();

			// Normal rules
			Set<NormalRule<L, S, W>> nRules = this.getNormalRulesEnding(t.getStart(), t.getLabel());
			for (NormalRule<L, S, W> r : nRules) {
				updatePrestar(worklist, new Transition<L, S>(r.getS1(), r.getL1(), t.getTarget()), (W) r.getWeight().extendWith(fa.getWeightFor(t)), fa);
			}

			// Push rules
			for (PushRule<L, S, W> r : this.getPushRules()) {
				if (r.getS2().equals(t.getStart()) && r.getL2().equals(t.getLabel())) {
					for (Transition<L, S> tdash : Sets.newHashSet(fa.getTransitionsOutOf(t.getTarget()))) {
						if (tdash.getLabel().equals(r.getCallSite())) {
							updatePrestar(worklist, new Transition<L, S>(r.getS1(), r.getL1(), tdash.getTarget()),
								(W) r.getWeight().extendWith(fa.getWeightFor(t)).extendWith(fa.getWeightFor(tdash)), fa);
						}
					}
				}
			}

			for (PushRule<L, S, W> r : this.getPushRules()) {
				if (r.getL2().equals(t.getLabel())) {
					for (Transition<L, S> tdash : Sets.newHashSet(fa.getTransitionsOutOf(r.getS2()))) {
						if (tdash.getLabel().equals(r.getCallSite()) && tdash.getTarget().equals(t.getStart())) {
							updatePrestar(worklist, new Transition<L, S>(r.getS1(), r.getL1(), t.getTarget()),
								(W) r.getWeight().extendWith(fa.getWeightFor(tdash)).extendWith(fa.getWeightFor(t)), fa);
						}
					}
				}
			}
		}

		return fa;
	}

	/**
	 * Add transition {@code trans} to fa, assign a weight to it that is computed of the rule's {@code weight} with that of the {@code previous} transitions.
	 *
	 * @param worklist
	 * @param t
	 * @param w
	 * @param fa
	 */
	protected void updatePrestar(LinkedList<Transition<L, S>> worklist, Transition<L, S> t, W w, WeightedAutomaton<L, S, W> fa) throws IllegalTransitionException {
		if (!fa.getTransitions().contains(t)) {
			fa.addTransition(t, null);
		}
		W oldWeight = fa.getWeightFor(t);
		W newWeight = (oldWeight == null) ? w : (W) oldWeight.combineWith(w);
		boolean changed = !newWeight.equals(oldWeight);
		if (changed) {
			fa.setWeightForTransition(t, newWeight);
			worklist.add(t);
		}
	}

	public String toString() {
		String s = "WPDS (#Rules: " + getAllRules().size() + ")\n";
		s += "\tNormalRules:\n\t\t";
		s += Joiner.on("\n\t\t").join(normalRules);
		s += "\n";
		s += "\tPopRules:\n\t\t";
		s += Joiner.on("\n\t\t").join(popRules);
		s += "\n";
		s += "\tPushRules:\n\t\t";
		s += Joiner.on("\n\t\t").join(pushRules);
		return s;
	}

	public abstract L epsilon();

}
