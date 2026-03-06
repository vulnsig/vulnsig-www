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
  className,
}: {
  title: string;
  metricKeys: string[];
  description: React.ReactNode;
  examples: LegendExample[];
  className?: string;
}) {
  return (
    <div
      className={`pb-10 border-b border-zinc-800 last:border-b-0 ${className ?? ""}`}
    >
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8">
        <LegendSection
          title="Color Hue"
          metricKeys={["Score"]}
          description="The glyph's overall color maps to the CVSS score. Red means critical (9-10), red-orange is high (7-8.9), orange is medium (4-6.9), and yellow is low (0.1-3.9). The color gives an instant indicator of severity."
          examples={[
            {
              label: "10.0",
              vector:
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            },
            {
              label: "8.7",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:L/SI:N/SA:N",
            },
            {
              label: "5.6",
              vector:
                "CVSS:4.0/AV:L/AC:H/AT:H/PR:H/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
            },
            {
              label: "2.3",
              vector:
                "CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
            },
          ]}
        />

        <LegendSection
          title="Star Points"
          metricKeys={["AV"]}
          description={
            <>
              Attack Vector describes how the vulnerability is exploited.{" "}
              <ValueTag label="N" /> Network means remote exploitation: 8
              points. <ValueTag label="A" /> Adjacent requires local network
              access: 6 points. <ValueTag label="L" /> Local needs OS-level
              access: 4 points. <ValueTag label="P" /> Physical requires
              touching the device: 3 points.
            </>
          }
          examples={[
            {
              label: "AV:N: 8",
              vector:
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "AV:A: 6",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "AV:L: 4",
              vector:
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "AV:P: 3",
              vector:
                "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
          ]}
        />

        <LegendSection
          title="Star Pointiness"
          metricKeys={["AC"]}
          description={
            <>
              Attack Complexity reflects conditions beyond the attacker&apos;s
              control. <ValueTag label="L" /> Low produces sharp star points:
              exploitation is straightforward. <ValueTag label="H" /> High
              produces blunt, rounded points: specific conditions must align.
            </>
          }
          examples={[
            {
              label: "AC:L: Sharp",
              vector:
                "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "AC:H: Blunt",
              vector:
                "CVSS:4.0/AV:P/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
          ]}
        />

        <LegendSection
          title="Star Outline"
          metricKeys={["PR"]}
          description={
            <>
              Privileges Required describes the level of access needed before
              exploitation. <ValueTag label="N" /> None shows a thin outline —
              no authentication needed. <ValueTag label="L" /> Low shows a
              medium stroke. <ValueTag label="H" /> High shows a thick outline —
              significant privileges required.
            </>
          }
          examples={[
            {
              label: "PR:N: Thin",
              vector:
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "PR:L: Medium",
              vector:
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "PR:H: Thick",
              vector:
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
          ]}
        />

        <LegendSection
          title="Trisection Ring Brightness"
          metricKeys={["VC", "VI", "VA"]}
          description={
            <>
              The trisection ring is divided into three sectors for
              Confidentiality, Integrity, and Availability.{" "}
              <ValueTag label="H" /> High lights a sector brightly,{" "}
              <ValueTag label="L" /> Low dims it, and <ValueTag label="N" />{" "}
              None leaves it dark.
            </>
          }
          examples={[
            {
              label: "All High",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "C High",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
            },
            {
              label: "A Low",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
            },
            {
              label: "A High, I Low",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N",
            },
          ]}
        />

        <LegendSection
          title="Trisection Ring Split"
          metricKeys={["SC", "SI", "SA"]}
          description="When a vulnerability impacts downstream systems (not just the vulnerable component), the trisection ring shows a split band. This indicates blast radius, i.e., the effects propagate beyond the original target."
          examples={[
            {
              label: "No downstream",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "High downstream",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            },
            {
              label: "Low downstream",
              vector:
                "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L",
            },
          ]}
        />

        <LegendSection
          title="Trisection Ring Segmentation"
          metricKeys={["AT"]}
          description={
            <>
              Attack Requirements describes if prerequisites in the vulnerable
              system&apos;s environment are required. <ValueTag label="P" />{" "}
              Present segments the ring with visible cuts.{" "}
              <ValueTag label="N" /> None keeps the ring smooth and continuous.
            </>
          }
          examples={[
            {
              label: "AT:N — Solid",
              vector:
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N",
            },
            {
              label: "AT:P — Segmented",
              vector:
                "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N",
            },
          ]}
        />

        <LegendSection
          title="Spikes & Bumps"
          metricKeys={["UI"]}
          description={
            <>
              User Interaction describes whether someone other than the attacker
              must participate. <ValueTag label="N" /> None produces spikes.{" "}
              <ValueTag label="P" /> Passive shows bumps. <ValueTag label="A" />{" "}
              Active produces a smooth edge.
            </>
          }
          examples={[
            {
              label: "UI:N: Spikes",
              vector:
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
            },
            {
              label: "UI:P: Bumps",
              vector:
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
            },
            {
              label: "UI:A: Smooth",
              vector:
                "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
            },
          ]}
        />

        <LegendSection
          title="Exploit Maturity"
          metricKeys={["E"]}
          description={
            <>
              Exploit Maturity is a CVSS 4.0 threat metric that adjusts the
              score based on real-world exploitation evidence.{" "}
              <ValueTag label="A" /> Attacked means active exploitation is
              confirmed: concentric rings appear behind the star.{" "}
              <ValueTag label="P" /> PoC means a proof-of-concept exists: a
              filled circle appears. <ValueTag label="U" /> Unproven and{" "}
              <ValueTag label="X" /> Not Defined produce no marker.
            </>
          }
          examples={[
            {
              label: "E:A: Rings",
              vector:
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:A",
            },
            {
              label: "E:P: Circle",
              vector:
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:P",
            },
            {
              label: "E:U: None",
              vector:
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N/E:U",
            },
          ]}
        />
      </div>

      {/* Summary table */}
      <div className="pb-10">
        <h3 className="text-lg font-semibold mb-4">Summary</h3>
        <div className="overflow-x-auto bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-zinc-500 border-b border-zinc-800">
                <th className="pb-2 pr-4 font-semibold">Visual</th>
                <th className="pb-2 pr-4 font-semibold">Metric</th>
                <th className="pb-2 font-semibold">Encoding</th>
              </tr>
            </thead>
            <tbody className="text-zinc-300">
              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Color Hue</td>
                <td className="py-2 pr-4">
                  <MetricTag label="Score" color={metricColor("Score")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Red=critical → yellow=low
                </td>
              </tr>

              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Star Points</td>
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
              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Star Pointiness</td>
                <td className="py-2 pr-4">
                  <MetricTag label="AC" color={metricColor("AC")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Sharp=
                  <ValueTag label="L" /> Blunt=
                  <ValueTag label="H" />
                </td>
              </tr>
              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Star Outline</td>
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

              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Trisection Ring Brightness</td>
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
              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Trisection Ring Split</td>
                <td className="py-2 pr-4 space-x-1">
                  <MetricTag label="SC" color={metricColor("SC")} />
                  <MetricTag label="SI" color={metricColor("SI")} />
                  <MetricTag label="SA" color={metricColor("SA")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Split when any &gt; <ValueTag label="N" />
                </td>
              </tr>

              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Trisection Ring Segmentation</td>
                <td className="py-2 pr-4">
                  <MetricTag label="AT" color={metricColor("AT")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Solid=
                  <ValueTag label="N" /> Segmented=
                  <ValueTag label="P" />
                </td>
              </tr>

              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Spikes & bumps</td>
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

              <tr className="border-b border-zinc-800">
                <td className="py-2 pr-4">Exploit Maturity</td>
                <td className="py-2 pr-4">
                  <MetricTag label="E" color={metricColor("E")} />
                </td>
                <td className="py-2 text-zinc-400">
                  Rings=
                  <ValueTag label="A" /> Circle=
                  <ValueTag label="P" /> None=
                  <ValueTag label="U" />/<ValueTag label="X" />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
