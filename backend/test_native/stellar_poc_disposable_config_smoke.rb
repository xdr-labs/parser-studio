# STDIN is a fixed synthetic CONF emitted by the reviewed TS compiler
# test-only transformer; no real customer source or live Fluentd listener.
require 'fluent/config'

def checked(condition, code)
  raise "Synthetic POC config AST failure: #{code}" unless condition
end
source = STDIN.read(16 * 1024)
checked(source.bytesize > 0 && source.bytesize < 12_000, 'CONF_SIZE')
checked(!source.include?('@include') && !source.include?('rewrite_tag_filter') &&
        !source.include?('<filter>'), 'NO_REAL_ROUTING')
name='customized_ps_api_crud_test_a1b2c3'
parsed=Fluent::Config.parse(source,'synthetic-poc-disposable.conf',nil,true)
children=parsed.elements
checked(children.length == 3,'EXACT_BLOCKS')
listeners=children.select{|x|x.name=='source'}
checked(listeners.length==2,'TWO_SOURCES')
checked(listeners.map{|x|x['@type']}.sort==%w[tcp udp],'PROTOCOLS')
listeners.each do |listener|
  checked(listener['bind']=='127.0.0.1','LOOPBACK')
  checked(listener['port']=='7891','TEST_PORT')
  checked(listener['tag']==name,'EXACT_TAG')
  checked(listener.elements.length==1 && listener.elements.first.name=='parse' &&
          listener.elements.first['@type']==name,'EXACT_PARSER')
end
out=children.select{|x|x.name=='match'}
checked(out.length==1 && out.first.arg==name+'.**' &&
        out.first['@type']=='null' && out.first.elements.empty?,'NULL_SINK_ONLY')
puts 'Fluentd disposable POC config AST: two loopback sources, reserved port and null sink PASS (synthetic only)'
