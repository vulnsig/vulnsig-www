"use client";

import { useState, useMemo, useCallback, useEffect } from "react";
import { VulnSig } from "vulnsig-react";
import { calculateScore } from "vulnsig";
import { useData } from "./DataContext";
import { VULNERABILITIES } from "@/data/vulnerabilities";
import type { CveEntry } from "./DataContext";

interface QuizEntry {
  id: string;
  vector: string;
}

function shuffle<T>(arr: T[]): T[] {
  const out = [...arr];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

// Strip the "CVSS:X.X/" version prefix so vectors that differ only in version
// (e.g. CVSS:3.0 vs CVSS:3.1) are treated as visually identical.
function vectorMetrics(vector: string): string {
  const i = vector.indexOf("/");
  return i !== -1 ? vector.slice(i + 1) : vector;
}

function buildDistractorPool(
  cves: CveEntry[],
  kevs: CveEntry[],
  excludeMetrics: Set<string>,
): QuizEntry[] {
  const seen = new Set<string>(excludeMetrics);
  const pool: QuizEntry[] = [];
  for (const c of [...cves, ...kevs]) {
    const key = vectorMetrics(c.cvss.vectorString);
    if (!seen.has(key)) {
      seen.add(key);
      pool.push({ id: c.id, vector: c.cvss.vectorString });
    }
  }
  return pool;
}

interface QuizQuestion {
  correct: QuizEntry;
  choices: QuizEntry[];
}

const DIFFICULTY_CHOICES = { easy: 3, challenging: 6, hard: 9 } as const;
type Difficulty = keyof typeof DIFFICULTY_CHOICES;

function generateQuestion(
  questionPool: QuizEntry[],
  distractorPool: QuizEntry[],
  numChoices: number,
  excludeVector?: string,
): QuizQuestion | null {
  const numDistractors = numChoices - 1;
  if (questionPool.length === 0 || distractorPool.length < numDistractors)
    return null;

  const available = excludeVector
    ? questionPool.filter((q) => q.vector !== excludeVector)
    : questionPool;
  if (available.length === 0) return null;

  const correct = available[Math.floor(Math.random() * available.length)];

  const correctMetrics = vectorMetrics(correct.vector);
  const distPool = distractorPool.filter(
    (d) => vectorMetrics(d.vector) !== correctMetrics,
  );
  const shuffledDistractors = shuffle(distPool).slice(0, numDistractors);
  if (shuffledDistractors.length < numDistractors) return null;

  const choices = shuffle([correct, ...shuffledDistractors]);
  return { correct, choices };
}

export function QuizTab() {
  const { cveData, kevData } = useData();

  const questionPool: QuizEntry[] = useMemo(
    () => VULNERABILITIES.map((v) => ({ id: v.name, vector: v.vector })),
    [],
  );

  const distractorPool = useMemo(
    () =>
      buildDistractorPool(
        cveData.cves,
        kevData.cves,
        new Set(questionPool.map((q) => vectorMetrics(q.vector))),
      ),
    [cveData, kevData, questionPool],
  );

  const [difficulty, setDifficulty] = useState<Difficulty>("easy");

  const [question, setQuestion] = useState<QuizQuestion | null>(() =>
    generateQuestion(questionPool, distractorPool, DIFFICULTY_CHOICES["easy"]),
  );
  const [wrongChoices, setWrongChoices] = useState<Set<string>>(new Set());
  const [solved, setSolved] = useState(false);
  const [lastMessage, setLastMessage] = useState<{
    text: string;
    correct: boolean;
    fading?: boolean;
  } | null>(null);
  const [showVector, setShowVector] = useState(false);
  const [score, setScore] = useState({ correct: 0, total: 0 });
  const [questionInitialized, setQuestionInitialized] = useState(false);

  // Derived state during render: when distractorPool first becomes available,
  // generate the initial question. React re-renders immediately and efficiently.
  // This avoids calling setState inside a useEffect (cascading render concern).
  if (!questionInitialized && distractorPool.length > 0) {
    setQuestionInitialized(true);
    setQuestion(
      generateQuestion(
        questionPool,
        distractorPool,
        DIFFICULTY_CHOICES[difficulty],
      ),
    );
  }

  useEffect(() => {
    if (!lastMessage || lastMessage.correct || lastMessage.fading) return;
    const fadeTimer = setTimeout(
      () => setLastMessage((prev) => (prev ? { ...prev, fading: true } : null)),
      1000,
    );
    const clearTimer = setTimeout(() => setLastMessage(null), 4000);
    return () => {
      clearTimeout(fadeTimer);
      clearTimeout(clearTimer);
    };
  }, [lastMessage]);

  const handleSelect = useCallback(
    (vector: string) => {
      if (solved || !question) return;
      if (wrongChoices.has(vector)) return;

      const isCorrect = vector === question.correct.vector;

      if (isCorrect) {
        setSolved(true);
        setLastMessage({ text: "Correct!", correct: true });
        setScore((prev) => ({
          correct: prev.correct + 1,
          total: prev.total + 1,
        }));
      } else {
        setWrongChoices((prev) => new Set([...prev, vector]));
        setLastMessage({
          text: "Try another glyph",
          correct: false,
        });
        setScore((prev) => ({ ...prev, total: prev.total + 1 }));
      }
    },
    [solved, question, wrongChoices],
  );

  const handleNext = useCallback(() => {
    const next = generateQuestion(
      questionPool,
      distractorPool,
      DIFFICULTY_CHOICES[difficulty],
      question?.correct.vector,
    );
    setQuestion(next);
    setWrongChoices(new Set());
    setSolved(false);
    setLastMessage(null);
    setShowVector(false);
  }, [question, questionPool, distractorPool, difficulty]);

  if (!question) {
    return <div className="text-zinc-500 text-sm">Loading quiz…</div>;
  }

  return (
    <div className="max-w-2xl mx-auto">
      {/* Difficulty selector */}
      <div className="flex items-center gap-3 mb-6">
        {/* <label className="text-sm text-zinc-500">Difficulty</label> */}
        <select
          value={difficulty}
          onChange={(e) => {
            const next = e.target.value as Difficulty;
            setDifficulty(next);
            setQuestion(
              generateQuestion(
                questionPool,
                distractorPool,
                DIFFICULTY_CHOICES[next],
              ),
            );
            setWrongChoices(new Set());
            setSolved(false);
            setLastMessage(null);
            setShowVector(false);
          }}
          className="text-xs font-mono bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-zinc-300 cursor-pointer"
        >
          <option value="easy">Easy (3 glyphs)</option>
          <option value="challenging">Challenging (6 glyphs)</option>
          <option value="hard">Hard (9 glyphs)</option>
        </select>
      </div>

      {/* Score tracker */}
      <div className="flex items-center justify-between mb-6">
        <p className="text-sm text-zinc-400">
          Score:{" "}
          <span className="text-zinc-200">
            {score.correct} / {score.total}
          </span>
        </p>
        {score.total > 0 && (
          <p className="text-sm text-zinc-500">
            {Math.round((score.correct / score.total) * 100)}% accuracy
          </p>
        )}
      </div>

      {/* Question card */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 mb-6 min-h-60">
        <p className="text-sm text-zinc-500 mb-2">
          Which glyph matches this vulnerability?
        </p>
        <div className="flex gap-2 mb-4">
          <h2 className="w-1/3 text-xl font-semibold text-zinc-100">
            {question.correct.id}
          </h2>
          <span className="w-2/3 text-sm text-zinc-400">
            {
              VULNERABILITIES.find((v) => v.name === question.correct.id)
                ?.description
            }
          </span>
        </div>
        <div className="relative">
          <p
            className={`font-mono text-xs break-all ${showVector ? "text-zinc-400" : "invisible"}`}
          >
            {question.correct.vector}
          </p>
          {!showVector && (
            <button
              onClick={() => setShowVector(true)}
              className="absolute top-0 left-0 text-xs font-mono text-zinc-500 hover:text-zinc-300 border border-zinc-700 hover:border-zinc-500 rounded px-3 py-1.5 transition-colors cursor-pointer"
            >
              Show CVSS vector
            </button>
          )}
        </div>
      </div>

      {/* Glyph choices */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {question.choices.map((choice) => {
          const choiceScore = calculateScore(choice.vector);
          const isCorrectChoice = choice.vector === question.correct.vector;
          const isWrong = wrongChoices.has(choice.vector);
          const isDisabled = solved || isWrong;

          let borderClass =
            "border-zinc-700 hover:border-zinc-500 cursor-pointer";
          if (solved && isCorrectChoice) {
            borderClass = "border-indigo-500/70";
          } else if (isWrong) {
            borderClass = "border-zinc-700 opacity-40 cursor-default";
          } else if (solved) {
            borderClass = "border-zinc-800 cursor-default";
          }

          return (
            <button
              key={choice.vector}
              onClick={() => handleSelect(choice.vector)}
              disabled={isDisabled}
              aria-label={`Glyph for ${choice.id}`}
              className={`bg-zinc-900 border rounded-lg p-4 flex flex-col items-center gap-2 transition-colors ${borderClass}`}
            >
              <VulnSig vector={choice.vector} size={100} score={choiceScore} />
            </button>
          );
        })}
      </div>

      {/* Feedback message */}
      <div className={`text-center mb-4 ${lastMessage ? "" : "invisible"}`}>
        <p
          className={`font-semibold mb-4 transition-opacity duration-1000 ${lastMessage?.fading ? "opacity-0" : "opacity-100"} ${lastMessage?.correct ? "text-indigo-300/90" : "text-zinc-400"}`}
        >
          {lastMessage?.text ?? "placeholder"}
        </p>
        <button
          onClick={handleNext}
          className={`text-sm font-mono text-zinc-400 hover:text-zinc-100 border border-zinc-700 hover:border-zinc-500 rounded px-3 py-1.5 transition-colors cursor-pointer ${solved ? "" : "invisible"}`}
        >
          Next question
        </button>
      </div>
    </div>
  );
}
