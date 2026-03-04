"use client";

import { useState, useMemo, useCallback } from "react";
import { VulnSig } from "vulnsig-react";
import { calculateScore } from "vulnsig";
import { ScoreBadge } from "./ScoreBadge";
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

function buildDistractorPool(
  cves: CveEntry[],
  kevs: CveEntry[],
): QuizEntry[] {
  const seen = new Set<string>();
  const pool: QuizEntry[] = [];
  for (const c of cves.slice(0, 40)) {
    if (!seen.has(c.cvss.vectorString)) {
      seen.add(c.cvss.vectorString);
      pool.push({ id: c.id, vector: c.cvss.vectorString });
    }
  }
  for (const c of kevs.slice(0, 40)) {
    if (!seen.has(c.cvss.vectorString)) {
      seen.add(c.cvss.vectorString);
      pool.push({ id: c.id, vector: c.cvss.vectorString });
    }
  }
  return pool;
}

interface QuizQuestion {
  correct: QuizEntry;
  choices: QuizEntry[];
}

function generateQuestion(
  questionPool: QuizEntry[],
  distractorPool: QuizEntry[],
  excludeVector?: string,
): QuizQuestion | null {
  if (questionPool.length === 0 || distractorPool.length < 2) return null;

  const available = excludeVector
    ? questionPool.filter((q) => q.vector !== excludeVector)
    : questionPool;
  if (available.length === 0) return null;

  const correct = available[Math.floor(Math.random() * available.length)];

  const distPool = distractorPool.filter(
    (d) => d.vector !== correct.vector,
  );
  const shuffledDistractors = shuffle(distPool).slice(0, 2);
  if (shuffledDistractors.length < 2) return null;

  const choices = shuffle([correct, ...shuffledDistractors]);
  return { correct, choices };
}

export function QuizTab() {
  const { cveData, kevData } = useData();

  const questionPool: QuizEntry[] = useMemo(
    () =>
      VULNERABILITIES.map((v) => ({ id: v.name, vector: v.vector })),
    [],
  );

  const distractorPool = useMemo(
    () => buildDistractorPool(cveData.cves, kevData.cves),
    [cveData, kevData],
  );

  const [question, setQuestion] = useState<QuizQuestion | null>(() =>
    generateQuestion(questionPool, distractorPool),
  );
  const [wrongChoices, setWrongChoices] = useState<Set<string>>(new Set());
  const [solved, setSolved] = useState(false);
  const [lastMessage, setLastMessage] = useState<{
    text: string;
    correct: boolean;
  } | null>(null);
  const [showVector, setShowVector] = useState(false);
  const [score, setScore] = useState({ correct: 0, total: 0 });

  const handleSelect = useCallback(
    (vector: string) => {
      if (solved || !question) return;
      if (wrongChoices.has(vector)) return;

      const isCorrect = vector === question.correct.vector;

      if (isCorrect) {
        setSolved(true);
        setLastMessage({ text: "✓ Correct! Well done.", correct: true });
        setScore((prev) => ({
          correct: prev.correct + 1,
          total: prev.total + 1,
        }));
      } else {
        setWrongChoices((prev) => new Set([...prev, vector]));
        setLastMessage({
          text: "✗ Not quite — try another glyph.",
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
      question?.correct.vector,
    );
    setQuestion(next);
    setWrongChoices(new Set());
    setSolved(false);
    setLastMessage(null);
    setShowVector(false);
  }, [question, questionPool, distractorPool]);

  if (!question) {
    return (
      <div className="text-zinc-500 text-sm">
        Loading quiz…
      </div>
    );
  }

  const questionScore = calculateScore(question.correct.vector);

  return (
    <div className="max-w-2xl mx-auto">
      {/* Score tracker */}
      <div className="flex items-center justify-between mb-6">
        <p className="text-sm text-zinc-400">
          Score:{" "}
          <span className="font-mono text-zinc-200">
            {score.correct} / {score.total}
          </span>
        </p>
        {score.total > 0 && (
          <p className="text-xs font-mono text-zinc-500">
            {Math.round((score.correct / score.total) * 100)}% accuracy
          </p>
        )}
      </div>

      {/* Question card */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 mb-6">
        <p className="text-xs font-mono text-zinc-500 mb-2">
          Which glyph matches this vulnerability?
        </p>
        <div className="flex items-center gap-3 mb-4">
          <h2 className="text-xl font-semibold text-zinc-100">
            {question.correct.id}
          </h2>
          <ScoreBadge score={questionScore} size="sm" />
        </div>
        {showVector ? (
          <p className="font-mono text-xs text-zinc-400 break-all">
            {question.correct.vector}
          </p>
        ) : (
          <button
            onClick={() => setShowVector(true)}
            className="text-xs font-mono text-zinc-500 hover:text-zinc-300 border border-zinc-700 hover:border-zinc-500 rounded px-3 py-1.5 transition-colors cursor-pointer"
          >
            Show CVSS vector
          </button>
        )}
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
            borderClass = "border-green-500";
          } else if (isWrong) {
            borderClass = "border-red-800 opacity-40 cursor-default";
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
              {solved && isCorrectChoice && (
                <p className="text-xs font-mono text-green-400">✓ correct</p>
              )}
              {isWrong && (
                <p className="text-xs font-mono text-red-500">✗ wrong</p>
              )}
            </button>
          );
        })}
      </div>

      {/* Feedback message */}
      {lastMessage && (
        <div className="text-center mb-4">
          <p
            className={`font-semibold mb-4 ${lastMessage.correct ? "text-green-400" : "text-red-400"}`}
          >
            {lastMessage.text}
          </p>
          {solved && (
            <button
              onClick={handleNext}
              className="text-sm font-mono text-zinc-400 hover:text-zinc-100 border border-zinc-700 hover:border-zinc-500 rounded px-4 py-2 transition-colors cursor-pointer"
            >
              Next question →
            </button>
          )}
        </div>
      )}
    </div>
  );
}
