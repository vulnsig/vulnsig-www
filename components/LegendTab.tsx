"use client";

import { VulnSig } from "vulnsig-react";

interface LegendExample {
  label: string;
  vector: string;
  score?: number;
}

function LegendSection({
  title,
  metric,
  description,
  examples,
}: {
  title: string;
  metric: string;
  description: string;
  examples: LegendExample[];
}) {
  return (
    <div className="pb-10 border-b border-zinc-800 last:border-b-0">
      <div className="mb-4">
        <h3 className="text-lg font-semibold mb-1">
          {title}
          <span className="text-xs font-mono text-zinc-500 ml-2">{metric}</span>
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
        metric="Score → Color"
        description="The glyph's overall color maps directly to the CVSS score. Red means critical (9-10), orange is high (7-8.9), yellow is medium (4-6.9), and green is low (0.1-3.9). The color gives an instant severity read before you examine any details."
        examples={[
          { label: "10.0", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", score: 10.0 },
          { label: "8.7", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N", score: 8.7 },
          { label: "5.6", vector: "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N", score: 5.6 },
          { label: "2.3", vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", score: 2.3 },
        ]}
      />

      <LegendSection
        title="Star Points"
        metric="AV — Attack Vector"
        description="Attack Vector describes how the vulnerability is exploited. Network (AV:N) means the attacker can exploit it remotely over the internet — the star has 8 points. Adjacent (AV:A) requires local network access (6 points). Local (AV:L) needs OS-level access (4 points). Physical (AV:P) means they need to physically touch the device (3 points)."
        examples={[
          { label: "AV:N — 8pts", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "AV:A — 6pts", vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "AV:L — 4pts", vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "AV:P — 3pts", vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
        ]}
      />

      <LegendSection
        title="Star Pointiness"
        metric="AC — Attack Complexity"
        description="Attack Complexity reflects conditions beyond the attacker's control that must exist to exploit the vulnerability. Low (AC:L) produces sharp star points — exploitation is straightforward. High (AC:H) produces blunt, rounded points — the attacker needs specific conditions to align."
        examples={[
          { label: "AC:L — Sharp", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "AC:H — Blunt", vector: "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
        ]}
      />

      <LegendSection
        title="Star Outline"
        metric="PR — Privileges Required"
        description="Privileges Required describes the level of access an attacker needs before exploitation. None (PR:N) shows a thin outline — no authentication needed. Low (PR:L) shows a medium stroke. High (PR:H) shows a thick outline — the attacker needs significant privileges."
        examples={[
          { label: "PR:N — Thin", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "PR:L — Medium", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "PR:H — Thick", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
        ]}
      />

      <LegendSection
        title="Ring Brightness"
        metric="VC/VI/VA — CIA Impact"
        description="The ring around the star is divided into three sectors representing Confidentiality, Integrity, and Availability impact. High impact lights a sector brightly, Low dims it, and None leaves it dark. You can see at a glance which aspects of the system are affected."
        examples={[
          { label: "All High", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "C only", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "A only", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "All None", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", score: 9.3 },
        ]}
      />

      <LegendSection
        title="Split Band"
        metric="SC/SI/SA — Subsequent System Impact"
        description="When a vulnerability impacts downstream systems (not just the vulnerable component), the ring shows a split band. This indicates blast radius — the vulnerability's effects propagate beyond the original target."
        examples={[
          { label: "No downstream", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "Full downstream", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", score: 10.0 },
        ]}
      />

      <LegendSection
        title="Ring Segmentation"
        metric="AT — Attack Requirements"
        description="Attack Requirements captures prerequisites that must exist in the vulnerable system's environment. When preconditions are needed (AT:P), the ring is segmented with visible cuts. When none are needed (AT:N), the ring is smooth and continuous."
        examples={[
          { label: "AT:N — Solid", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "AT:P — Segmented", vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
        ]}
      />

      <LegendSection
        title="Spikes and Bumps"
        metric="UI — User Interaction"
        description="User Interaction describes whether someone other than the attacker must participate. None (UI:N) produces spikes — the vulnerability fires autonomously. Passive (UI:P) shows bumps — the user encounters the exploit during normal use. Active (UI:A) produces a smooth edge — the user must deliberately take action."
        examples={[
          { label: "UI:N — Spikes", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "UI:P — Bumps", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
          { label: "UI:A — Smooth", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score: 9.3 },
        ]}
      />

      <LegendSection
        title="Star Fill"
        metric="Score → Center"
        description="The star's center is filled with the score color at full intensity. Combined with the ring color, this creates a cohesive severity visualization where the inner shape and outer ring reinforce the same message."
        examples={[
          { label: "Critical", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", score: 10.0 },
          { label: "Medium", vector: "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N", score: 5.6 },
          { label: "Low", vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", score: 2.3 },
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
                <td className="py-2 pr-4 font-mono text-xs">AV</td>
                <td className="py-2 text-zinc-400">8=N, 6=A, 4=L, 3=P</td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Star pointiness</td>
                <td className="py-2 pr-4 font-mono text-xs">AC</td>
                <td className="py-2 text-zinc-400">Sharp=L, Blunt=H</td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Star outline</td>
                <td className="py-2 pr-4 font-mono text-xs">PR</td>
                <td className="py-2 text-zinc-400">Thin=N, Medium=L, Thick=H</td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Spikes / bumps</td>
                <td className="py-2 pr-4 font-mono text-xs">UI</td>
                <td className="py-2 text-zinc-400">Spikes=N, Bumps=P, Smooth=A</td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Ring segmentation</td>
                <td className="py-2 pr-4 font-mono text-xs">AT</td>
                <td className="py-2 text-zinc-400">Solid=N, Segmented=P</td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Ring brightness</td>
                <td className="py-2 pr-4 font-mono text-xs">VC/VI/VA</td>
                <td className="py-2 text-zinc-400">Bright=H, Dim=L, Dark=N</td>
              </tr>
              <tr className="border-b border-zinc-800/50">
                <td className="py-2 pr-4">Split band</td>
                <td className="py-2 pr-4 font-mono text-xs">SC/SI/SA</td>
                <td className="py-2 text-zinc-400">Split when any &gt; N</td>
              </tr>
              <tr>
                <td className="py-2 pr-4">Color hue</td>
                <td className="py-2 pr-4 font-mono text-xs">Score</td>
                <td className="py-2 text-zinc-400">Red=critical → green=low</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
