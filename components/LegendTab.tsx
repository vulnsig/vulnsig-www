"use client";

import { VulnSig } from "vulnsig-react";
import { MetricTag, ValueTag, metricColor } from "./MetricTag";

interface LegendExample {
  label: string;
  vector: string;
  score?: number;
}

function LegendSection({
  title,
  metricKeys,
  description,
  examples,
}: {
  title: string;
  metricKeys: string[];
  description: React.ReactNode;
  examples: LegendExample[];
}) {
  return (
    <div className="pb-10 border-b border-zinc-800 last:border-b-0">
      <div className="mb-4">
        <h3 className="text-lg font-semibold mb-1 flex items-center gap-2">
          {title}
          {metricKeys.map((k) => (
            <MetricTag key={k} label={k} color={metricColor(k)} />
          ))}
        </h3>
        <p className="text-sm text-zinc-400 leading-relaxed">{description}</p>
      </div>
      <div className="flex flex-wrap gap-6 items-end">
        {examples.map((ex) => (
          <div key={ex.label} className="flex flex-col items-center gap-2">
            <VulnSig vector={ex.vector} size={80} score={ex.score} />
            <span className="text-xs font-mono text-zinc-500">{ex.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function LegendTab() {
  return (
    <div className="space-y-10">
      <LegendSection
        title="Color Hue"
        metricKeys={["Score"]}
        description="The glyph's overall color maps directly to the CVSS score. Red means critical (9-10), orange is high (7-8.9), yellow is medium (4-6.9), and green is low (0.1-3.9). The color gives an instant severity read before you examine any details."
        examples={[
          {
            label: "10.0",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            score: 10.0,
          },
          {
            label: "8.7",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N",
            score: 8.7,
          },
          {
            label: "5.6",
            vector:
              "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
            score: 5.6,
          },
          {
            label: "2.3",
            vector:
              "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            score: 2.3,
          },
        ]}
      />

      <LegendSection
        title="Star Points"
        metricKeys={["AV"]}
        description={
          <>
            Attack Vector describes how the vulnerability is exploited.{" "}
            <ValueTag label="N" /> Network means remote exploitation — 8 points.{" "}
            <ValueTag label="A" /> Adjacent requires local network access — 6
            points. <ValueTag label="L" /> Local needs OS-level access — 4
            points. <ValueTag label="P" /> Physical requires touching the device
            — 3 points.
          </>
        }
        examples={[
          {
            label: "AV:N — 8pts",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "AV:A — 6pts",
            vector:
              "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "AV:L — 4pts",
            vector:
              "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "AV:P — 3pts",
            vector:
              "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
        ]}
      />

      <LegendSection
        title="Star Pointiness"
        metricKeys={["AC"]}
        description={
          <>
            Attack Complexity reflects conditions beyond the attacker&apos;s
            control. <ValueTag label="L" /> Low produces sharp star points —
            exploitation is straightforward. <ValueTag label="H" /> High
            produces blunt, rounded points — specific conditions must align.
          </>
        }
        examples={[
          {
            label: "AC:L — Sharp",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "AC:H — Blunt",
            vector:
              "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
        ]}
      />

      <LegendSection
        title="Star Outline"
        metricKeys={["PR"]}
        description={
          <>
            Privileges Required describes the level of access needed before
            exploitation. <ValueTag label="N" /> None shows a thin outline — no
            authentication needed. <ValueTag label="L" /> Low shows a medium
            stroke. <ValueTag label="H" /> High shows a thick outline —
            significant privileges required.
          </>
        }
        examples={[
          {
            label: "PR:N — Thin",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "PR:L — Medium",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "PR:H — Thick",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
        ]}
      />

      <LegendSection
        title="Ring Brightness"
        metricKeys={["VC", "VI", "VA"]}
        description={
          <>
            The ring is divided into three sectors for Confidentiality,
            Integrity, and Availability. <ValueTag label="H" /> High lights a
            sector brightly, <ValueTag label="L" /> Low dims it, and{" "}
            <ValueTag label="N" /> None leaves it dark.
          </>
        }
        examples={[
          {
            label: "All High",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "C only",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "A only",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "All None",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            score: 9.3,
          },
        ]}
      />

      <LegendSection
        title="Split Band"
        metricKeys={["SC", "SI", "SA"]}
        description="When a vulnerability impacts downstream systems (not just the vulnerable component), the ring shows a split band. This indicates blast radius — the effects propagate beyond the original target."
        examples={[
          {
            label: "No downstream",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "Full downstream",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            score: 10.0,
          },
        ]}
      />

      <LegendSection
        title="Ring Segmentation"
        metricKeys={["AT"]}
        description={
          <>
            Attack Requirements captures prerequisites in the vulnerable
            system&apos;s environment. <ValueTag label="P" /> Present segments
            the ring with visible cuts. <ValueTag label="N" /> None keeps the
            ring smooth and continuous.
          </>
        }
        examples={[
          {
            label: "AT:N — Solid",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "AT:P — Segmented",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
        ]}
      />

      <LegendSection
        title="Spikes and Bumps"
        metricKeys={["UI"]}
        description={
          <>
            User Interaction describes whether someone other than the attacker
            must participate. <ValueTag label="N" /> None produces spikes —
            fires autonomously. <ValueTag label="P" /> Passive shows bumps —
            encountered during normal use. <ValueTag label="A" /> Active
            produces a smooth edge — deliberate action required.
          </>
        }
        examples={[
          {
            label: "UI:N — Spikes",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "UI:P — Bumps",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
          {
            label: "UI:A — Smooth",
            vector:
              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            score: 9.3,
          },
        ]}
      />

      {/* Summary table */}
      <div className="pb-10">
        <h3 className="text-lg font-semibold mb-4">Summary</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-zinc-500 border-b border-zinc-800">
                <th className="pb-2 pr-4 font-mono font-normal">Visual</th>
                <th className="pb-2 pr-4 font-mono font-normal">Metric</th>
                <th className="pb-2 font-mono font-normal">Encoding</th>
              </tr>
            </thead>
            <tbody className="text-zinc-300">
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Star points</td>
                <td className="py-2 pr-4">
                  <MetricTag label="AV" color={metricColor("AV")} />
                </td>
                <td className="py-2 text-zinc-400">
                  8=
                  <ValueTag label="N" /> 6=
                  <ValueTag label="A" /> 4=
                  <ValueTag label="L" /> 3=
                  <ValueTag label="P" />
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Star pointiness</td>
                <td className="py-2 pr-4">
                  <MetricTag label="AC" color={metricColor("AC")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Sharp=
                  <ValueTag label="L" /> Blunt=
                  <ValueTag label="H" />
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Star outline</td>
                <td className="py-2 pr-4">
                  <MetricTag label="PR" color={metricColor("PR")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Thin=
                  <ValueTag label="N" /> Medium=
                  <ValueTag label="L" /> Thick=
                  <ValueTag label="H" />
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Spikes / bumps</td>
                <td className="py-2 pr-4">
                  <MetricTag label="UI" color={metricColor("UI")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Spikes=
                  <ValueTag label="N" /> Bumps=
                  <ValueTag label="P" /> Smooth=
                  <ValueTag label="A" />
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Ring segmentation</td>
                <td className="py-2 pr-4">
                  <MetricTag label="AT" color={metricColor("AT")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Solid=
                  <ValueTag label="N" /> Segmented=
                  <ValueTag label="P" />
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Ring brightness</td>
                <td className="py-2 pr-4 space-x-1">
                  <MetricTag label="VC" color={metricColor("VC")} />
                  <MetricTag label="VI" color={metricColor("VI")} />
                  <MetricTag label="VA" color={metricColor("VA")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Bright=
                  <ValueTag label="H" /> Dim=
                  <ValueTag label="L" /> Dark=
                  <ValueTag label="N" />
                </td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Split band</td>
                <td className="py-2 pr-4 space-x-1">
                  <MetricTag label="SC" color={metricColor("SC")} />
                  <MetricTag label="SI" color={metricColor("SI")} />
                  <MetricTag label="SA" color={metricColor("SA")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Split when any &gt; <ValueTag label="N" />
                </td>
              </tr>
              <tr>
                <td className="py-2 pr-4">Color hue</td>
                <td className="py-2 pr-4">
                  <MetricTag label="Score" color={metricColor("Score")} />
                </td>
                <td className="py-2 text-zinc-400">Red=critical → green=low</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
