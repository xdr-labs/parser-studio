# Check the local synthetic native test subprocess limits, not a general sandbox.
cpu_soft, = Process.getrlimit(Process::RLIMIT_CPU)
memory_soft, = Process.getrlimit(Process::RLIMIT_AS)
cpu_budget = 30
memory_budget = 1024 * 1024 * 1024
unless cpu_soft.is_a?(Integer) && cpu_soft > 0 && cpu_soft <= cpu_budget &&
       memory_soft.is_a?(Integer) && memory_soft > 0 && memory_soft <= memory_budget
  raise 'Native synthetic Ruby subprocess is not resource-bounded'
end
puts "Native Ruby subprocess limits: CPU <= #{cpu_budget}s, virtual memory <= #{memory_budget} bytes PASS"
