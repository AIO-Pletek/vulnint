/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  experimental: { typedRoutes: false },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${process.env.NEXT_PUBLIC_API_INTERNAL_URL || "http://api:8000"}/api/:path*`,
      },
    ];
  },
};
module.exports = nextConfig;
