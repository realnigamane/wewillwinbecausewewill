/** @type {import('next').NextConfig} */
export default {
  transpilePackages: ['@liqarch/shared'],
  experimental: { serverComponentsExternalPackages: ['postgres'] },
};
