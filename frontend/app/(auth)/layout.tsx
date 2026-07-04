export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid-backdrop flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm">{children}</div>
    </div>
  );
}
