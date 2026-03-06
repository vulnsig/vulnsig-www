interface VulnSigLogoProps {
  /** Color for the top arc */
  color1?: string;
  /** Color for the right arc */
  color2?: string;
  /** Color for the left arc */
  color3?: string;
  size?: number;
  className?: string;
}

export function VulnSigLogo({
  color1 = "#939598",
  color2 = "#939598",
  color3 = "#939598",
  size = 144,
  className,
}: VulnSigLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 144.01 143.9"
      className={className}
    >
      {/* Top arc */}
      <path
        d="M72.01,0C46.31,0,23.71,13.53,10.97,33.84l34.69,20.03c5.77-8.37,15.43-13.87,26.35-13.87s20.57,5.49,26.35,13.86l34.68-20.02C120.3,13.53,97.7,0,72.01,0Z"
        fill={color1}
        style={{ transition: "fill 0.1s ease" }}
      />
      {/* Right arc */}
      <path
        d="M136.91,40.83l-34.87,20.13c1.28,3.44,1.97,7.16,1.97,11.04,0,16.3-12.24,29.79-28.01,31.76v40.14c37.85-2.08,68.01-33.53,68.01-71.9,0-11.16-2.55-21.73-7.1-31.17Z"
        fill={color2}
        style={{ transition: "fill 0.1s ease" }}
      />
      {/* Left arc */}
      <path
        d="M40,72c0-3.87.69-7.59,1.97-11.03L7.1,40.84C2.55,50.28,0,60.85,0,72c0,38.36,30.15,69.81,68,71.9v-40.14c-15.77-1.98-28-15.47-28-31.76Z"
        fill={color3}
        style={{ transition: "fill 0.1s ease" }}
      />
    </svg>
  );
}
