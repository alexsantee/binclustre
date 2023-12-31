from angrutils import *

def generate_cg(cfg, fname, outputpath):
    # vis = AngrVisFactory().default_cg_pipeline(kb, verbose=verbose)
    # vis.set_output(DotOutput(fname, format=format))
    # vis.process(kb, filter)
    vis = AngrVisFactory().default_cg_pipeline(cfg.kb, verbose=False)
    vis.set_output(_DotOutput(fname, outputpath))
    vis.process(cfg.kb, None)

class _DotOutput(Output):

    def __init__(self, fname, outputpath):
        super(_DotOutput, self).__init__()
        self.fname = fname
        self.outputpath = outputpath
        # self.format = format
        # self.show = show
        # self.pause = pause

    def render_attributes(self, default, attrs):
        a = {}
        a.update(default)
        a.update(attrs)
        r = []
        for k,v in a.items():
            r.append(k+"="+v)

        return "["+", ".join(r)+"]"

    def render_cell(self, key, data):
        if data != None and data['content'] != None and data['content'].strip() != '':
            # ret = '<TD '+ ('bgcolor="'+data['bgcolor']+'" ' if 'bgcolor' in data else '') + ('ALIGN="'+data['align']+'"' if 'align' in data else '' )+'>'
            # if 'color' in data:
            #     ret += '<FONT COLOR="'+data['color']+'">'
            # if 'style' in data:
            #     ret += '<'+data['style']+'>'
            ret = ''
            #'content': "<TABLE><TR><TD>" +  "</TD></TR><TR><TD>".join(self.cllog[key]) + "</TD></TR></TABLE>",
            if isinstance(data['content'], list):
                # ret += '<TABLE BORDER="0">'
                for c in data['content']:
                    # ret += '<TR><TD ' + ('ALIGN="'+data['align']+'"' if 'align' in data else '' )+'>'
                    ret += escape(c)
                    # ret += '</TD></TR>'
                # ret += '</TABLE>'
            else:
                ret += escape(data['content'])
            # if 'style' in data:
            #     ret += '</'+data['style']+'>'
            # if 'color' in data:
            #     ret += '</FONT>'
            # ret += "</TD>"
            return ret
        else:
            # return "<TD></TD>"
            return ''

    def render_row(self, row, colmeta):
        # ret = "<TR>"
        ret = ""
        for k in colmeta:
            ret += self.render_cell(k, row[k] if k in row else None)
        # ret += "</TR>"
        return ret

    def render_content(self, c):
        ret = ''
        if len(c['data']) > 0:
            # ret = '<TABLE BORDER="0" CELLPADDING="1" ALIGN="LEFT">'
            ret = ''
            for r in c['data']:
                ret += self.render_row(r, c['columns'])
            # ret += '</TABLE>'
        return ret

    def render_node(self, n):
        # attrs = {}
        # if n.style:
        #     attrs['style'] = n.style
        # if n.fillcolor:
        #     attrs['fillcolor'] = '"'+n.fillcolor+'"'
        # if n.color:
        #     attrs['color'] = n.color
        # if n.width:
        #     attrs['penwidth'] = str(n.width)
        # if n.url:
        #     attrs['URL'] = '"'+n.url+'"'
        # if n.tooltip:
        #     attrs['tooltip'] = '"'+n.tooltip+'"'


        label = "|".join([self.render_content(c) for c in n.content.values()])
        # if label:
        #     # attrs['label'] = '<{ %s }>' % label
        #     attrs['label'] = '%s' % label

        #label = '<TABLE ROWS="*" BORDER="1" STYLE="ROUNDED" CELLSPACING="4" CELLPADDING="0" CELLBORDER="0"><TR><TD FIXEDSIZE="FALSE" ALIGN="LEFT">' + '</TD></TR><TR><TD FIXEDSIZE="FALSE"  ALIGN="LEFT">'.join([self.render_content(c) for c in n.content.values()]) + "</TD></TR></TABLE>"
        #if label:
        #    attrs['label'] = '<%s>' % label


        # return "%s %s" % (str(n.seq), self.render_attributes(default_node_attributes, attrs))
        return "%s %s" % (str(n.seq), label)

    def render_edge(self, e):
        attrs = {}
        # if e.color:
        #     attrs['color'] = e.color
        # if e.label:
        #     attrs['label'] = '"'+e.label+'"'
        # if e.style:
        #     attrs['style'] = e.style
        # if e.width:
        #     attrs['penwidth'] = str(e.width)
        # if e.weight:
        #     attrs['weight'] = str(e.weight)

        # return "%s -> %s %s" % (str(e.src.seq), str(e.dst.seq), self.render_attributes(default_edge_attributes, attrs))
        return "%s -> %s " % (str(e.src.seq), str(e.dst.seq))


    def generate_cluster_label(self, label):
        rendered = ""

        if label is None:
            pass
        elif isinstance(label, list):
            rendered = ""
            # rendered += "<BR ALIGN=\"left\"/>"
            for l in label:
                rendered += escape(l)
                # rendered += "<BR ALIGN=\"left\"/>"
        else:
            rendered += escape(label)

        # return 'label=< %s >;' % rendered
        return rendered

    def generate_cluster(self, graph, cluster):
        ret = ""
        if cluster:
            ret += "subgraph " + ("cluster" if cluster.visible else "X") + "_" + str(graph.seqmap[cluster.key]) + "{\n"
            ret += self.generate_cluster_label(cluster.label)+"\n"
            # if cluster.style:
            #     ret +='style="%s";\n' % cluster.style
            # if cluster.fillcolor:
            #     ret +='color="%s";\n' % cluster.fillcolor

        nodes = list(filter(lambda n:n.cluster == cluster, graph.nodes))

        try:
            if len(nodes) > 0:
                nodes = sorted(nodes, key=lambda n: n.obj.addr)
        except:
            # if the nodes don't have address
            pass

        for n in nodes:
            ret += self.render_node(n) + "\n"

        if cluster:
            for child_cluster in graph.get_clusters(cluster):
                ret += self.generate_cluster(graph, child_cluster)

        if cluster:
            ret += "}\n"
        return ret

    def generate(self, graph):
        ret  = "digraph \"\" {\n"
        # ret += "rankdir=TB;\n"
        # ret += "newrank=true;\n"
        # for some clusters graphviz ignores the alignment specified in BR
        # but does the alignment based on this value (possible graphviz bug)
        # ret += "labeljust=l;\n"

        for cluster in graph.get_clusters():
            ret += self.generate_cluster(graph, cluster)

        ret += self.generate_cluster(graph, None)

        for e in graph.edges:
            ret += self.render_edge(e) + "\n"

        ret += "}\n"

        # if self.show:
        #     p = Popen(['xdot', '-'], stdin=PIPE)
        #     p.stdin.write(ret)
        #     p.stdin.flush()
        #     p.stdin.close()
        #     if self.pause:
        #         p.wait()

        # print(ret)
        with open(f"{self.outputpath}/{self.fname}", "w") as outputfile:
            outputfile.write(ret)

        # if self.fname:
        #     dotfile = XDot(ret)
            # print(dotfile.to_string())
            # dotfile.write("{}.{}".format(self.fname, self.format), format=self.format)
